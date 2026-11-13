"""``messages.build_cr`` and shared-secret ``protect`` and ``verify_protection`` (RFC 9810 sec. 5.1.3.1, 5.3.3).

Provenance: the four ``ir`` requests of ``tests/vectors/openssl-3.5.6-cmp-ir-pbm.json`` were
written by ``openssl cmp`` (OpenSSL 3.5.6), not by this package. ``protect`` must reproduce the
protection bytes OpenSSL wrote, and the header bytes too, since the MAC covers them; that pins the
header rebuild and the key rule against a second implementation. The ``cr`` requests, the PBMAC1
and the AES-GMAC cases are this package's own round trips, checked against the MAC functions that
``test_protection.py`` pins against OpenSSL.
"""

from __future__ import annotations

import datetime
import json
import pathlib

import pytest
from asn1core import decode, decode_oid

from enrollkit import _der
from enrollkit.bodies import cert_req_messages_content
from enrollkit.crmf import cert_req_msg, cert_request
from enrollkit.messages import (
    CMP_2000,
    build_cr,
    build_message,
    check_header_9483,
    is_null_dn,
    parse,
)
from enrollkit.protection import (
    ID_AES128_GMAC,
    ID_PBMAC1,
    KEY_BASEKEY,
    GmacParameter,
    Pbmac1Parameter,
    PbmParameter,
    ProtectionError,
    protect,
    read_pbm_algorithm,
    verify_protection,
)

VECTORS = json.loads(
    (pathlib.Path(__file__).parent / "vectors" / "openssl-3.5.6-cmp-ir-pbm.json").read_text()
)
PASSWORD = VECTORS["password"].encode()
SHA256 = "2.16.840.1.101.3.4.2.1"
HMAC_SHA256 = "1.2.840.113549.2.9"
SECRET = b"shared-secret-with-enough-entropy"
TXID = bytes(range(16))
NONCE = bytes(range(16, 32))
NOW = datetime.datetime(2026, 11, 13, 12, 0, tzinfo=datetime.UTC)
SUBJECT = _der.sequence(
    _der.tlv(_der.Tag(17, True), _der.sequence(_der.oid("2.5.4.3"), _der.utf8_string("device-1")))
)
# a template with a subject and no key: build_cr does not look inside the CertReqMessages
TEMPLATE = _der.sequence(_der.context(5, SUBJECT))
REQUEST = cert_req_messages_content(cert_req_msg(cert_request(1, TEMPLATE)))


def cr(**options):
    defaults = {"transaction_id": TXID, "sender_nonce": NONCE, "message_time": NOW}
    return build_cr(REQUEST, "device-ref-1", "Example CA", **(defaults | options))


def read_alg_oid(message):
    node, _ = decode(message.header.protection_alg)
    return ".".join(str(arc) for arc in decode_oid(node.children[0].payload))


def test_build_cr():
    message = cr(implicit_confirm=True, cert_profile=("tls-server",))
    # RFC 9810 sec. 5.3.3: the body is the cr alternative holding the CertReqMessages as given
    assert message.body_name == "cr"
    assert message.body_raw == _der.context(2, REQUEST)
    header = message.header
    # RFC 9483 sec. 3.1 for MAC-based protection: sender is a commonName, senderKID repeats it
    assert header.sender[0] == 0xA4  # a directoryName [4]
    assert header.sender_kid == b"device-ref-1"
    assert b"device-ref-1" in header.sender
    assert b"Example CA" in header.recipient
    assert header.pvno == CMP_2000
    assert (header.transaction_id, header.sender_nonce) == (TXID, NONCE)
    assert header.message_time == NOW
    # an unprotected message: no protectionAlg and no protection (sec. 5.1.1)
    assert header.protection_alg is None
    assert message.protection is None
    # the only RFC 9483 rule left is the one protect() satisfies
    assert check_header_9483(header, "cr", first_message=True, protection="mac") == (
        "protectionAlg is REQUIRED",
    )
    assert (
        check_header_9483(
            protect(message, SECRET).header, "cr", first_message=True, protection="mac"
        )
        == ()
    )


def test_build_cr_defaults_and_refusals():
    # nonces are fresh 128 random bits per message; the recipient defaults to the NULL-DN
    a = build_cr(REQUEST, "ref", None)
    b = build_cr(REQUEST, "ref", None)
    assert is_null_dn(a.header.recipient)
    assert len(a.header.transaction_id or b"") == 16 == len(a.header.sender_nonce or b"")
    assert (a.header.transaction_id, a.header.sender_nonce) != (
        b.header.transaction_id,
        b.header.sender_nonce,
    )
    with pytest.raises(ValueError, match="SEQUENCE"):
        build_cr(b"\x04\x00", "ref", None)
    with pytest.raises(ValueError, match="empty"):
        build_cr(REQUEST, "", None)


def test_protect_reproduces_the_openssl_protection():
    for name, raw in VECTORS["requests"].items():
        captured = parse(bytes.fromhex(raw))
        assert captured.header.protection_alg is not None
        stripped = parse(_der.sequence(captured.header_raw, captured.body_raw))
        assert stripped.protection is None
        again = protect(stripped, PASSWORD, rule=KEY_BASEKEY)
        # the header is rebuilt from its fields, keeping protectionAlg as written (OpenSSL leaves
        # out the NULL parameters of the OWF and the MAC), and comes out as the bytes OpenSSL wrote
        assert again.header_raw == captured.header_raw, name
        assert again.protection == captured.protection, name
        verify_protection(captured, PASSWORD, rule=KEY_BASEKEY)


def test_verify_protection_follows_the_key_rule():
    # RFC 9810 sec. 5.1.3.1 against OpenSSL: the two readings agree only when K equals H
    outcomes = {}
    for name, raw in VECTORS["requests"].items():
        try:
            verify_protection(parse(bytes.fromhex(raw)), PASSWORD)
            outcomes[name] = True
        except ProtectionError:
            outcomes[name] = False
    assert outcomes == {
        "sha256_owf_hmacWithSHA256": True,
        "sha256_owf_hmacSHA1_ipsec_oid": False,
        "sha256_owf_hmacWithSHA1": False,
        "sha1_owf_hmacWithSHA256": False,
    }


def test_protect():
    message = cr()
    protected = protect(message, SECRET)
    assert protected.protection is not None
    assert protected.body_raw == message.body_raw
    assert protected.header.transaction_id == TXID
    assert protected.header.sender_kid == b"device-ref-1"
    # the default is PBM with SHA-256 and HMAC-SHA256 at 10,000 iterations and a fresh salt
    assert protected.header.protection_alg is not None
    parameter = read_pbm_algorithm(protected.header.protection_alg)
    assert (parameter.owf, parameter.mac, parameter.iterations) == (SHA256, HMAC_SHA256, 10_000)
    assert len(parameter.salt) == 16
    assert (
        parameter.salt
        != read_pbm_algorithm(protect(message, SECRET).header.protection_alg or b"").salt
    )
    verify_protection(protected, SECRET)
    # a protected message re-protected under another algorithm replaces both fields
    again = protect(
        protected,
        SECRET,
        parameter=PbmParameter(b"saltsalt", SHA256, 500, HMAC_SHA256),
    )
    assert again.header.protection_alg != protected.header.protection_alg
    verify_protection(again, SECRET)
    # extraCerts survive, and are not part of what is protected
    with_certs = parse(
        build_message(
            message.header_raw, "cr", REQUEST, extra_certs=[_der.sequence(_der.integer(1))]
        )
    )
    assert protect(with_certs, SECRET).extra_certs == with_certs.extra_certs


def test_protect_with_pbmac1_and_gmac():
    message = cr()
    pbmac1 = Pbmac1Parameter(bytes(range(16)), 1000, 32, HMAC_SHA256, HMAC_SHA256)
    protected = protect(message, SECRET, parameter=pbmac1)
    assert protected.protection is not None
    assert ID_PBMAC1 in {read_alg_oid(protected)}
    verify_protection(protected, SECRET)
    gmac = GmacParameter(ID_AES128_GMAC, bytes(range(12)))
    key = bytes(range(16))
    protected = protect(message, key, parameter=gmac)
    assert len(protected.protection or b"") == 16
    verify_protection(protected, key)
    with pytest.raises(ProtectionError):
        verify_protection(protected, bytes(16))


def test_verify_protection_refuses_what_does_not_verify():
    protected = protect(cr(), SECRET)
    with pytest.raises(ProtectionError, match="does not verify"):
        verify_protection(protected, b"another secret")
    # one flipped bit of the body, of the header, or of the protection is caught
    raw = _der.sequence(
        protected.header_raw,
        protected.body_raw[:-1] + bytes([protected.body_raw[-1] ^ 1]),
        _der.context(0, _der.bit_string(protected.protection or b"")),
    )
    with pytest.raises(ProtectionError):
        verify_protection(parse(raw), SECRET)
    flipped = bytes([(protected.protection or b"\x00")[0] ^ 1]) + (protected.protection or b"")[1:]
    raw = _der.sequence(
        protected.header_raw, protected.body_raw, _der.context(0, _der.bit_string(flipped))
    )
    with pytest.raises(ProtectionError):
        verify_protection(parse(raw), SECRET)
    # no protection at all, and protection with no protectionAlg (sec. 5.1.1), are both refused
    with pytest.raises(ProtectionError, match="no protection"):
        verify_protection(cr(), SECRET)
    unprotected_alg = parse(
        _der.sequence(
            cr().header_raw, cr().body_raw, _der.context(0, _der.bit_string(b"\x00" * 32))
        )
    )
    with pytest.raises(ProtectionError, match="protectionAlg is missing"):
        verify_protection(unprotected_alg, SECRET)


def test_verify_protection_never_passes_a_signature_algorithm():
    from enrollkit.messages import build_header

    algorithm = _der.sequence(_der.oid("1.2.840.113549.1.1.11"), _der.null())
    header = build_header(
        pvno=CMP_2000,
        sender=cr().header.sender,
        recipient=cr().header.recipient,
        protection_alg=algorithm,
        transaction_id=TXID,
        sender_nonce=NONCE,
    )
    message = parse(
        _der.sequence(header, cr().body_raw, _der.context(0, _der.bit_string(b"\x01" * 64)))
    )
    with pytest.raises(NotImplementedError, match=r"protection.signature"):
        verify_protection(message, SECRET)
