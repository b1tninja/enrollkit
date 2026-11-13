"""POPOSIMESTAMP, POPOWITNESS and signature protection (RFC 9810).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import TYPE_CHECKING

from asn1core import Asn1Error, Node, TagClass, check_integer, decode, decode_oid

from . import _der

if TYPE_CHECKING:
    from typing import Any

    PkiMessage = Any  # placeholder: give it a real type in the milestone that needs it
    Trust = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "ID_PASSWORD_BASED_MAC",
    "PbmError",
    "PbmParameter",
    "pbm_algorithm_identifier",
    "pbm_key",
    "pbm_mac",
    "pbm_verify",
    "protect",
    "protected_part",
    "read_pbm_algorithm",
    "verify_protection",
]


def protect(msg: PkiMessage, secret: bytes) -> PkiMessage:
    """Pending behaviour defined by RFC 9810 sec. 5.1.3.

    Not implemented yet. See the ``protection.protect()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("protect() is not implemented: RFC 9810 sec. 5.1.3")


def verify_protection(msg: PkiMessage, trust: Trust) -> None:
    """Pending behaviour defined by RFC 9810 sec. 5.1.3.

    Not implemented yet. See the ``protection.verify_protection()`` row in ROADMAP.md;
    this stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("verify_protection() is not implemented: RFC 9810 sec. 5.1.3")


_ALG_ITEMS = 2
_OCTET_STRING = 4


# --------------------------------------------------------------------------------------------
# PasswordBasedMac (RFC 4211 sec. 4.4 as updated by RFC 9045; key expansion RFC 9810 sec. 5.1.3.1)

ID_PASSWORD_BASED_MAC = "1.2.840.113533.7.66.13"  # noqa: S105 - an OID
MIN_ITERATIONS = 100  # RFC 4211 sec. 4.4, kept by RFC 9045 sec. 4.3: "MUST be a minimum of 100"
# Policy bound, not protocol: the iterationCount is attacker-supplied on receipt, and an
# unbounded loop is a denial of service.
MAX_ITERATIONS = 10_000_000
_SALT_ADVISED = 8  # RFC 4211 sec. 4.4: the salt SHOULD be at least 8 octets

_OWF = {
    "1.3.14.3.2.26": "sha1",  # RFC 4211 sec. 4.4: all implementations MUST support SHA-1
    "2.16.840.1.101.3.4.2.1": "sha256",  # RFC 9045 sec. 4.2: replaces SHA-1 as the MUST
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}
_MAC = {
    "1.3.6.1.5.5.8.1.2": "sha1",  # id-hmacWithSHA1
    "1.2.840.113549.2.9": "sha256",  # id-hmacWithSHA256, RFC 9045 sec. 4.4
    "1.2.840.113549.2.10": "sha384",
    "1.2.840.113549.2.11": "sha512",
}


class PbmError(Exception):
    """PBMParameter is malformed, unsupported or outside policy."""


@dataclass(frozen=True, slots=True)
class PbmParameter:
    """PBMParameter (RFC 4211 sec. 4.4): the salt, OWF and MAC OIDs and the iteration count."""

    salt: bytes
    owf: str
    iterations: int
    mac: str

    def __post_init__(self) -> None:
        if self.owf not in _OWF:
            raise PbmError(f"unsupported one-way function {self.owf}")
        if self.mac not in _MAC:
            raise PbmError(f"unsupported MAC algorithm {self.mac}")
        if not MIN_ITERATIONS <= self.iterations <= MAX_ITERATIONS:
            raise PbmError(
                f"iterationCount {self.iterations} is outside {MIN_ITERATIONS}..{MAX_ITERATIONS}"
            )

    def short_salt(self) -> bool:
        """RFC 4211 sec. 4.4: the salt SHOULD be at least 8 octets."""
        return len(self.salt) < _SALT_ADVISED


def pbm_algorithm_identifier(parameter: PbmParameter) -> bytes:
    """The protectionAlg AlgorithmIdentifier for id-PasswordBasedMac with these parameters."""
    owf = _der.sequence(_der.oid(parameter.owf), _der.null())
    # RFC 9045 sec. 4.4: the HMAC parameters SHOULD be present and then MUST be NULL.
    mac = _der.sequence(_der.oid(parameter.mac), _der.null())
    body = _der.sequence(
        _der.octet_string(parameter.salt), owf, _der.integer(parameter.iterations), mac
    )
    return _der.sequence(_der.oid(ID_PASSWORD_BASED_MAC), body)


def _oid(node: Node) -> str:
    return ".".join(str(arc) for arc in decode_oid(node.payload or b""))


def read_pbm_algorithm(algorithm: bytes) -> PbmParameter:
    """Parse a protectionAlg TLV that must be id-PasswordBasedMac.

    Raises:
        PbmError: another algorithm, malformed parameters, or parameters outside policy.
    """
    try:
        node, end = decode(algorithm, der=True)
        if end != len(algorithm) or len(node.children) != _ALG_ITEMS:
            raise PbmError("AlgorithmIdentifier must be SEQUENCE { OID, PBMParameter }")
        if _oid(node.children[0]) != ID_PASSWORD_BASED_MAC:
            raise PbmError("protectionAlg is not id-PasswordBasedMac")
        salt, owf, count, mac = node.children[1].children
        if salt.tag.tag_class is not TagClass.universal or salt.tag.number != _OCTET_STRING:
            raise PbmError("PBMParameter.salt must be an OCTET STRING")
        return PbmParameter(
            salt=salt.payload or b"",
            owf=_oid(owf.children[0]),
            iterations=check_integer(count.payload or b""),
            mac=_oid(mac.children[0]),
        )
    except (Asn1Error, ValueError, IndexError) as error:
        raise PbmError(f"PBMParameter is malformed: {error}") from error


def pbm_key(secret: bytes, parameter: PbmParameter) -> bytes:
    """Derive the MAC key: OWF applied ``iterationCount`` times to ``secret || salt``.

    RFC 4211 sec. 4.4 gives the loop. When the MAC key is longer than the OWF output (K > H),
    RFC 9810 sec. 5.1.3.1 MUST-requires the expansion ``BASEKEY || OWF("1" || BASEKEY) || ...``.
    For HMAC the RFCs do not name K; this takes K as the MAC hash's output size, so
    HMAC-SHA256 over a SHA-1 OWF expands to 32 octets. That reading is recorded in ROADMAP.md.
    """
    owf = _OWF[parameter.owf]
    key = secret + parameter.salt
    for _ in range(parameter.iterations):
        key = hashlib.new(owf, key).digest()
    want = hashlib.new(_MAC[parameter.mac]).digest_size
    if want <= len(key):
        return key[:want]
    out = key
    counter = 1
    while len(out) < want:
        out += hashlib.new(owf, str(counter).encode("ascii") + key).digest()
        counter += 1
    return out[:want]


def pbm_mac(secret: bytes, parameter: PbmParameter, data: bytes) -> bytes:
    """HMAC of ``data`` under the derived key; ``data`` is the DER ``ProtectedPart``."""
    return hmac.new(pbm_key(secret, parameter), data, _MAC[parameter.mac]).digest()


def pbm_verify(secret: bytes, parameter: PbmParameter, data: bytes, value: bytes) -> bool:
    """Constant-time comparison of a received PKIProtection against the computed MAC."""
    return hmac.compare_digest(pbm_mac(secret, parameter, data), value)


def protected_part(header_der: bytes, body_der: bytes) -> bytes:
    """``ProtectedPart ::= SEQUENCE { header PKIHeader, body PKIBody }`` (RFC 9810 sec. 5.1.3).

    ``body_der`` is the PKIBody TLV, the ``[n]`` alternative, as it travels in the message.
    """
    return _der.sequence(header_der, body_der)
