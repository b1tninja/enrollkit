"""CertReqMessages, certConf, pollReq, pollRep and error bodies (RFC 9810 sec. 5.3).

Provenance: RFC 9810 prints no encoded body. The expected bytes below are written by hand, octet by
octet, from the ASN.1 of sec. 5.2.3, 5.3.18, 5.3.21 and 5.3.22 (Appendix F is an ``EXPLICIT TAGS``
module), so they share no code with the builders. The certificates for the certHash rule are minted
with ``cryptography`` and hashed with ``hashlib``. No vendor capture; ROADMAP.md keeps that row open.
"""

from __future__ import annotations

import datetime
import hashlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.x509.oid import NameOID
from test_pkiheader import ALG, NAME, NULL_DN, TXID

from enrollkit.bodies import (
    POLL_ALL,
    PollEntry,
    cert_conf_content,
    cert_hash,
    cert_hash_name,
    cert_req_messages_content,
    cert_status,
    error_content,
    p10cr_content,
    pki_status_info,
    poll_rep_content,
    poll_req_content,
    read_cert_conf,
    read_error,
    read_poll_rep,
    read_poll_req,
    read_status_info,
)
from enrollkit.messages import CMP_2000, MessageError, build_header, build_message, parse

SHA256_ALG = bytes.fromhex("300d06096086480165030402010500")


def message(body, content):
    header = build_header(
        pvno=CMP_2000,
        sender=NULL_DN,
        recipient=NAME,
        protection_alg=ALG,
        transaction_id=TXID,
    )
    return parse(build_message(header, body, content, protection=b"x" * 8))


def test_ir_cr_certconf_pollreq_round_trip():
    # a CertReqMessages is a non-empty SEQUENCE OF CertReqMsg
    msg = bytes.fromhex("3003020100")  # a stand-in SEQUENCE; crmf builds real ones
    assert cert_req_messages_content(msg) == bytes.fromhex("30053003020100")
    assert cert_req_messages_content(msg, msg) == bytes.fromhex("300a30030201003003020100")
    with pytest.raises(ValueError, match="at least one"):
        cert_req_messages_content()
    with pytest.raises(ValueError, match="SEQUENCE"):
        cert_req_messages_content(b"\x02\x01\x00")
    parsed = message("ir", cert_req_messages_content(msg))
    assert parsed.body_name == "ir"
    # certConf: hash, id, then statusInfo and hashAlg when present
    status = cert_status(bytes.fromhex("aabbccdd"), 0)
    assert status == bytes.fromhex("30090404aabbccdd020100")
    assert cert_conf_content(status) == bytes.fromhex("300b" + status.hex())
    parsed = message("certConf", cert_conf_content(status))
    (entry,) = read_cert_conf(parsed)
    assert (entry.cert_hash, entry.cert_req_id) == (bytes.fromhex("aabbccdd"), 0)
    assert entry.status_info is None
    assert entry.hash_alg is None
    # pollReq: one SEQUENCE { certReqId } per id, -1 for the complete response
    content = poll_req_content(0, POLL_ALL)
    assert content == bytes.fromhex("300a300302010030030201ff")
    assert read_poll_req(message("pollReq", content)) == (0, -1)
    # pollRep: certReqId, checkAfter and an optional PKIFreeText
    content = poll_rep_content([PollEntry(0, 30, ("wait",)), PollEntry(1, 5)])
    assert content == bytes.fromhex("3018300e02010002011e30060c04776169743006020101020105")
    assert read_poll_rep(message("pollRep", content)) == (
        PollEntry(0, 30, ("wait",)),
        PollEntry(1, 5, ()),
    )


def test_cert_status_info_and_hash_alg_are_read_back():
    info = pki_status_info(2, status_string=["no"], fail_info={1, 9})
    assert info == bytes.fromhex("300e02010230040c026e6f0303064040")
    status = cert_status(b"\x01" * 4, 7, status_info=info, hash_alg=SHA256_ALG)
    content = cert_conf_content(status, cert_status(b"\x02" * 4, 8))
    first, second = read_cert_conf(message("certConf", content))
    assert first.cert_req_id == 7
    assert first.status_info is not None
    assert first.status_info.status == 2
    assert first.status_info.status_string == ("no",)
    assert first.status_info.fail_info == frozenset({1, 9})
    assert first.hash_alg == SHA256_ALG
    assert second.status_info is None
    # an empty CertConfirmContent rejects every certificate (sec. 5.3.18 para 5)
    assert cert_conf_content() == b"\x30\x00"
    assert read_cert_conf(message("certConf", cert_conf_content())) == ()


def test_failure_info_is_a_dernamed_bit_string():
    # trailing zero bits are removed (X.690 sec. 11.2.2): badMessageCheck alone is 06 40
    assert pki_status_info(2, fail_info={1}) == bytes.fromhex("300702010203020640")
    assert pki_status_info(2, fail_info={0}) == bytes.fromhex("300702010203020780")
    assert pki_status_info(2, fail_info={26}) == bytes.fromhex("300a02010203050500000020")
    assert pki_status_info(2, fail_info=set()) == bytes.fromhex("3006020102030100")
    with pytest.raises(ValueError, match="0 to 26"):
        pki_status_info(2, fail_info={27})
    # round trip through the reader, every bit
    for bit in range(27):
        node = _node(pki_status_info(2, fail_info={bit}))
        assert read_status_info(node).fail_info == frozenset({bit})


def _node(der):
    from asn1core import decode

    return decode(der)[0]


@pytest.mark.parametrize(
    "bad",
    [
        b"\x30\x00",  # no status
        bytes.fromhex("3009020102030100030100"),  # repeated failInfo
        bytes.fromhex("30050201023000"),  # an empty PKIFreeText
        bytes.fromhex("3006020102030108"),  # unused bits 8 on an empty string
        b"\x02\x01\x00",  # not a SEQUENCE
    ],
)
def test_malformed_status_info_is_refused(bad):
    with pytest.raises(MessageError):
        read_status_info(_node(bad))


def test_malformed_bodies_are_refused():
    with pytest.raises(MessageError, match="not a certConf"):
        read_cert_conf(message("pollReq", poll_req_content(0)))
    for bad in (b"\x30\x03\x02\x01\x00", bytes.fromhex("300530030401aa")):
        with pytest.raises(MessageError):
            read_cert_conf(message("certConf", bad))
    with pytest.raises(MessageError):
        read_poll_req(message("pollReq", b"\x30\x02\x30\x00"))
    with pytest.raises(MessageError, match="negative"):
        read_poll_rep(message("pollRep", bytes.fromhex("300830060201000201ff")))
    with pytest.raises(ValueError, match="at least one"):
        poll_req_content()
    with pytest.raises(ValueError, match="-1"):
        poll_req_content(-2)
    with pytest.raises(ValueError, match="negative"):
        poll_rep_content([PollEntry(0, -1)])


def test_error_message_content_and_its_waiting_status():
    waiting = error_content(pki_status_info(3), error_code=7, error_details=["slow"])
    assert waiting == bytes.fromhex("3010300302010302010730060c04736c6f77")
    got = read_error(message("error", waiting))
    assert got.status_info.status == 3
    assert got.error_code == 7
    assert got.error_details == ("slow",)
    bare = read_error(message("error", error_content(pki_status_info(2))))
    assert bare.error_code is None
    with pytest.raises(MessageError):
        read_error(message("error", b"\x30\x00"))
    with pytest.raises(MessageError, match="not a error"):
        read_error(message("pollRep", poll_rep_content([PollEntry(0, 1)])))


def test_p10cr_carries_the_request_as_is():
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "device")]))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )
    assert p10cr_content(csr) == csr
    assert message("p10cr", p10cr_content(csr)).body_name == "p10cr"
    with pytest.raises(ValueError, match="one DER SEQUENCE"):
        p10cr_content(csr + b"\x00")
    with pytest.raises(ValueError, match="DER"):
        p10cr_content(b"\x30\x80\x00\x00")  # indefinite length is not DER


# --- certHash (sec. 5.3.18 para 3, RFC 9481 sec. 3.3 para 7) -----------------------------------


def cert_signed_by(key, algorithm, *, padding_=None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    return builder.sign(key, algorithm).public_bytes(serialization.Encoding.DER)


def test_cert_hash_follows_the_signature_algorithm():
    p256 = ec.generate_private_key(ec.SECP256R1())
    for algorithm, name in (
        (hashes.SHA256(), "sha256"),
        (hashes.SHA384(), "sha384"),
        (hashes.SHA512(), "sha512"),
    ):
        der = cert_signed_by(p256, algorithm)
        assert cert_hash_name(der) == name
        assert cert_hash(der) == hashlib.new(name, der).digest()
    rsa_key = rsa.generate_private_key(65537, 2048)
    der = cert_signed_by(rsa_key, hashes.SHA384())
    assert cert_hash_name(der) == "sha384"
    # EdDSA: SHA-512 for Ed25519, SHAKE256 with d=512 for Ed448 (RFC 9481 sec. 3.3 para 7)
    der = cert_signed_by(ed25519.Ed25519PrivateKey.generate(), None)
    assert cert_hash_name(der) == "sha512"
    assert cert_hash(der) == hashlib.sha512(der).digest()
    der = cert_signed_by(ed448.Ed448PrivateKey.generate(), None)
    assert cert_hash_name(der) == "shake256"
    assert cert_hash(der) == hashlib.shake_256(der).digest(64)
    assert len(cert_hash(der)) == 64
    # an explicit name overrides the table
    assert cert_hash(der, "sha256") == hashlib.sha256(der).digest()
    with pytest.raises(ValueError, match="DER"):
        cert_hash_name(b"not a certificate")


def test_cert_hash_refuses_rsassa_pss():
    rsa_key = rsa.generate_private_key(65537, 2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    pss = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(rsa_key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(
            rsa_key,
            hashes.SHA256(),
            rsa_padding=padding.PSS(padding.MGF1(hashes.SHA256()), 32),
        )
        .public_bytes(serialization.Encoding.DER)
    )
    with pytest.raises(ValueError, match="no certHash hash"):
        cert_hash_name(pss)  # the hash is in the parameters: the caller says which, via hashAlg
