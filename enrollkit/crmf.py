"""CRMF request objects, keys and proof of possession (RFC 4211, RFC 9045).

``build_request`` is a placeholder until the milestone named in ROADMAP.md lands; a stub raises
instead of returning a plausible empty value. The signature proof of possession is implemented:
``certificate_template``, ``cert_request``, ``sign_pop``, ``cert_req_msg`` and ``verify_pop``.

The CRMF module (RFC 4211 Appendix B) is ``IMPLICIT TAGS``, so a ``[n]`` over a SEQUENCE replaces
its tag, while a ``[n]`` over a CHOICE (``Name``, ``Time``) is explicit.

RFC 4211 sec. 4.1 as printed says the case-3 signature covers the "DER-encoded certificate
template"; verified erratum 4797 corrects that to the DER-encoded ``certReq`` (the CertRequest,
which is what its own field text says). This module signs ``certReq``.
"""

from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

from asn1core import Asn1Error, Node, TagClass, decode, decode_oid, encode_utc_time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from . import _der

if TYPE_CHECKING:
    from typing import Any

    CrmfRequest = Any  # placeholder: give it a real type in the milestone that needs it
    Validity = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "PopError",
    "build_request",
    "cert_req_msg",
    "cert_request",
    "certificate_template",
    "sign_pop",
    "spki_der",
    "verify_pop",
]

ID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
ID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"
ID_ED25519 = "1.3.101.112"

_POP_SIGNATURE = 1  # ProofOfPossession ::= CHOICE { ..., signature [1] POPOSigningKey, ... }
_BIT_STRING = 3
_SEQUENCE = 16
_NOT_BEFORE = 0
_NOT_AFTER = 1
_TEMPLATE_VALIDITY = 4
_TEMPLATE_SUBJECT = 5
_TEMPLATE_PUBLIC_KEY = 6
_MSG_ITEMS = 2
_POPOSK_ITEMS = 2  # algorithmIdentifier and signature; a third (poposkInput) would lead them

PublicKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey
PrivateKey = rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey | ed25519.Ed25519PrivateKey


class PopError(Exception):
    """A proof of possession is malformed, unsupported, or does not verify."""


def spki_der(public_key: PublicKey) -> bytes:
    """DER SubjectPublicKeyInfo of a ``cryptography`` public key."""
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def certificate_template(
    spki: bytes,
    subject: bytes,
    *,
    not_before: datetime.datetime | None = None,
    not_after: datetime.datetime | None = None,
) -> bytes:
    """CertTemplate (RFC 4211 sec. 5) carrying a subject, a public key and optionally validity.

    ``spki`` is the DER SubjectPublicKeyInfo and ``subject`` the DER Name. Fields are written in
    tag order; only the three this client sets are supported. A validity bound is a UTCTime, so
    it must fall in 1950..2049 (asn1core refuses other years).
    """
    parts = []
    if not_before is not None or not_after is not None:
        times = []
        if not_before is not None:
            utc = _der.tlv(_der.Tag(23), encode_utc_time(not_before))
            times.append(_der.context(_NOT_BEFORE, utc))
        if not_after is not None:
            utc = _der.tlv(_der.Tag(23), encode_utc_time(not_after))
            times.append(_der.context(_NOT_AFTER, utc))
        parts.append(_der.context(_TEMPLATE_VALIDITY, b"".join(times)))
    parts.append(_der.context(_TEMPLATE_SUBJECT, subject))  # Name is a CHOICE: explicit
    node, end = decode(spki, der=True)
    if end != len(spki) or node.tag.number != _SEQUENCE:
        raise ValueError("spki is not one DER SubjectPublicKeyInfo")
    parts.append(_der.context(_TEMPLATE_PUBLIC_KEY, node.content()))  # implicit over a SEQUENCE
    return _der.sequence(*parts)


def cert_request(cert_req_id: int, template: bytes) -> bytes:
    """CertRequest ::= SEQUENCE { certReqId INTEGER, certTemplate CertTemplate, ... }."""
    return _der.sequence(_der.integer(cert_req_id), template)


def sign_pop(private_key: PrivateKey, request: bytes) -> bytes:
    """Build ``signature [1] POPOSigningKey`` over the DER ``certReq`` (RFC 4211 sec. 4.1, case 3).

    ``poposkInput`` is omitted, which sec. 4.1 allows only when the template holds both the public
    key and a subject name; ``verify_pop`` enforces that. The signature is over ``request`` as
    given, per verified erratum 4797. RSA signs PKCS#1 v1.5 with SHA-256, EC signs ECDSA with
    SHA-256 and Ed25519 signs the bytes.
    """
    if isinstance(private_key, rsa.RSAPrivateKey):
        algorithm = _der.sequence(_der.oid(ID_SHA256_WITH_RSA), _der.null())
        signature = private_key.sign(request, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        algorithm = _der.sequence(_der.oid(ID_ECDSA_WITH_SHA256))
        signature = private_key.sign(request, ec.ECDSA(hashes.SHA256()))
    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        algorithm = _der.sequence(_der.oid(ID_ED25519))
        signature = private_key.sign(request)
    else:
        raise TypeError("private_key must be an RSA, EC or Ed25519 private key")
    return _der.context(_POP_SIGNATURE, algorithm + _der.bit_string(signature))


def cert_req_msg(request: bytes, pop: bytes | None = None) -> bytes:
    """CertReqMsg ::= SEQUENCE { certReq CertRequest, popo ProofOfPossession OPTIONAL, ... }."""
    return _der.sequence(request, *((pop,) if pop is not None else ()))


def verify_pop(message: bytes, public_key: PublicKey) -> None:
    """Check the signature proof of possession of one CertReqMsg against ``public_key``.

    The key must also be the one the template carries, so a valid signature by another key does
    not pass. Only the case-3 form (no ``poposkInput``) is accepted; the other two cases need a
    PKMACValue or an authenticated sender and are rows in ROADMAP.md. ``raVerified`` is refused:
    RFC 4211 sec. 4 says an RA/CA MUST NOT accept it from the requestor.

    Raises:
        PopError: anything wrong, including a signature that does not verify.
    """
    try:
        root, end = decode(message, der=True)
        if end != len(message) or root.tag.number != _SEQUENCE or not root.children:
            raise PopError("CertReqMsg must be SEQUENCE { certReq, popo }")
        if len(root.children) != _MSG_ITEMS:
            raise PopError("the request carries no proofOfPossession")
        request, popo = root.children
        if popo.tag.tag_class is not TagClass.context or popo.tag.number != _POP_SIGNATURE:
            raise PopError("proofOfPossession is not the signature alternative")
        if len(popo.children) != _POPOSK_ITEMS or popo.children[0].tag.number != _SEQUENCE:
            raise PopError("poposkInput is present or POPOSigningKey is malformed (case 3 only)")
        algorithm, bits = popo.children
        if algorithm.tag.number != _SEQUENCE or bits.tag.number != _BIT_STRING:
            raise PopError("POPOSigningKey must be { AlgorithmIdentifier, BIT STRING }")
        if not bits.payload or bits.payload[0] != 0:
            raise PopError("signature must be a whole-octet BIT STRING")
        _check_template_key(request.children[1], public_key)
        oid = ".".join(str(arc) for arc in decode_oid(algorithm.children[0].payload or b""))
        _verify(public_key, oid, bits.payload[1:], request.raw)
    except (Asn1Error, IndexError, ValueError) as error:
        raise PopError(f"CertReqMsg is malformed: {error}") from error


def _check_template_key(template: Node, public_key: PublicKey) -> None:
    subject = key = None
    for field in template.children:
        if field.tag.tag_class is not TagClass.context:
            continue
        if field.tag.number == _TEMPLATE_SUBJECT:
            subject = field
        elif field.tag.number == _TEMPLATE_PUBLIC_KEY:
            key = field
    if subject is None or key is None:
        raise PopError("case 3 needs both a subject and a publicKey in the template")
    if _der.sequence(key.content()) != spki_der(public_key):
        raise PopError("the template's publicKey is not the key being proven")


def _verify(public_key: PublicKey, algorithm: str, signature: bytes, data: bytes) -> None:
    try:
        if algorithm == ID_SHA256_WITH_RSA and isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        elif algorithm == ID_ECDSA_WITH_SHA256 and isinstance(
            public_key, ec.EllipticCurvePublicKey
        ):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        elif algorithm == ID_ED25519 and isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, data)
        else:
            raise PopError(f"signature algorithm {algorithm} does not match the key type")
    except InvalidSignature as error:
        raise PopError("proof of possession signature does not verify") from error


def build_request(public_key: object, subject: str, validity: Validity) -> CrmfRequest:
    """Pending behaviour defined by RFC 4211 sec. 5.

    Not implemented yet. See the ``crmf.build_request()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code. The pieces it will
    compose, ``certificate_template`` and ``cert_request``, exist; what is missing is turning
    a ``str`` subject into a DER Name.
    """
    raise NotImplementedError("build_request() is not implemented: RFC 4211 sec. 5")
