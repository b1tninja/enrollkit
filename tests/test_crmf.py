"""CRMF proof of possession, RFC 4211 sec. 4.1 with verified erratum 4797.

Provenance: keys are generated per test with ``cryptography``. The signature input is checked
independently: the test slices the certReq and the template out of the message and verifies the
POP bytes with ``cryptography`` directly, so the erratum (sign certReq, not the bare
certTemplate that the RFC text prints) is pinned by a second reader of the same bytes.
"""

from __future__ import annotations

import datetime

import pytest
from asn1core import decode
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from enrollkit import _der
from enrollkit.crmf import (
    PopError,
    cert_req_msg,
    cert_request,
    certificate_template,
    sign_pop,
    spki_der,
    verify_pop,
)

SUBJECT = _der.sequence(
    _der.tlv(_der.Tag(17, True), _der.sequence(_der.oid("2.5.4.3"), _der.utf8_string("device-1")))
)
EC = ec.generate_private_key(ec.SECP256R1())


def make(key, *, pop_key=None):
    template = certificate_template(
        spki_der(key.public_key()),
        SUBJECT,
        not_before=datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC),
        not_after=datetime.datetime(2027, 1, 1, tzinfo=datetime.UTC),
    )
    request = cert_request(0, template)
    return request, cert_req_msg(request, sign_pop(pop_key or key, request))


def test_proof_of_possession_verifies():
    for key in (
        rsa.generate_private_key(65537, 2048),
        ec.generate_private_key(ec.SECP256R1()),
        ed25519.Ed25519PrivateKey.generate(),
    ):
        _, msg = make(key)
        verify_pop(msg, key.public_key())
    # Independent reading of the bytes: the signature covers certReq, not the template (4797).
    key = EC
    request, msg = make(key)
    root, _ = decode(msg)
    req, popo = root.children
    assert req.raw == request
    signature = (popo.children[1].payload or b"")[1:]
    key.public_key().verify(signature, req.raw, ec.ECDSA(hashes.SHA256()))
    with pytest.raises(InvalidSignature):
        key.public_key().verify(signature, req.children[1].raw, ec.ECDSA(hashes.SHA256()))
    # the RSA path is PKCS#1 v1.5 with SHA-256
    rsa_key = rsa.generate_private_key(65537, 2048)
    request, msg = make(rsa_key)
    root, _ = decode(msg)
    signature = (root.children[1].children[1].payload or b"")[1:]
    rsa_key.public_key().verify(signature, request, padding.PKCS1v15(), hashes.SHA256())


def test_template_wire_shape():
    template = certificate_template(spki_der(EC.public_key()), SUBJECT)
    node, _ = decode(template)
    subject, key = node.children
    assert (subject.tag.number, subject.tag.constructed) == (5, True)
    assert subject.children[0].raw == SUBJECT  # CHOICE: explicit wrapper
    assert key.tag.number == 6  # SEQUENCE: implicit tag replaces the SEQUENCE tag
    assert b"\x30" + key.raw[1:] == spki_der(EC.public_key())


def test_pop_refuses_tampering_wrong_key_and_missing_pieces():
    request, msg = make(EC)
    with pytest.raises(PopError):
        verify_pop(msg.replace(b"device-1", b"device-2"), EC.public_key())
    other = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(PopError):
        verify_pop(msg, other.public_key())  # not the key in the template
    with pytest.raises(PopError):
        verify_pop(cert_req_msg(request), EC.public_key())  # no popo
    with pytest.raises(PopError):
        verify_pop(msg[:-1], EC.public_key())
    raverified = cert_req_msg(request, _der.context(0, b"", constructed=False))
    with pytest.raises(PopError):
        verify_pop(raverified, EC.public_key())  # RFC 4211 sec. 4: requestor MUST NOT set it
    _, forged = make(EC, pop_key=other)
    with pytest.raises(PopError):
        verify_pop(forged, EC.public_key())
    no_subject = cert_request(
        0, _der.sequence(_der.context(6, decode(spki_der(EC.public_key()))[0].content()))
    )
    with pytest.raises(PopError):
        verify_pop(cert_req_msg(no_subject, sign_pop(EC, no_subject)), EC.public_key())
