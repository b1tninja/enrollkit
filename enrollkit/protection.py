"""PKIMessage protection with a shared secret: PBM, PBMAC1 and AES-GMAC (RFC 9810 sec. 5.1.3.1).

``protect`` and ``verify_protection`` apply and check it on a ``PkiMessage``. Signature protection
(sec. 5.1.3.3) is not built and raises ``NotImplementedError`` rather than passing: see the
``protection.signature`` row in ROADMAP.md.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

from asn1core import Asn1Error, Node, TagClass, check_integer, decode, decode_oid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import _der
from .messages import PkiMessage, build_header, parse

__all__ = [
    "ID_AES128_GMAC",
    "ID_AES192_GMAC",
    "ID_AES256_GMAC",
    "ID_PASSWORD_BASED_MAC",
    "ID_PBMAC1",
    "KEY_BASEKEY",
    "KEY_RFC9810",
    "GmacParameter",
    "PbmError",
    "PbmParameter",
    "Pbmac1Parameter",
    "ProtectionError",
    "gmac_algorithm_identifier",
    "gmac_mac",
    "gmac_verify",
    "pbm_algorithm_identifier",
    "pbm_key",
    "pbm_mac",
    "pbm_verify",
    "pbmac1_algorithm_identifier",
    "pbmac1_key",
    "pbmac1_mac",
    "pbmac1_verify",
    "protect",
    "protected_part",
    "read_gmac_algorithm",
    "read_pbm_algorithm",
    "read_pbmac1_algorithm",
    "verify_protection",
]


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

_SHA256_OID = "2.16.840.1.101.3.4.2.1"  # RFC 9045 sec. 4.2: the MUST one-way function
_HMAC_SHA256_OID = "1.2.840.113549.2.9"  # id-hmacWithSHA256, RFC 9045 sec. 4.4: the MUST MAC
_OWF = {
    "1.3.14.3.2.26": "sha1",  # RFC 4211 sec. 4.4: all implementations MUST support SHA-1
    "2.16.840.1.101.3.4.2.1": "sha256",  # RFC 9045 sec. 4.2: replaces SHA-1 as the MUST
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}
_MAC = {
    "1.3.6.1.5.5.8.1.2": "sha1",  # hMAC-SHA1 in the IPsec arc, as RFC 4210 and OpenSSL write it
    "1.2.840.113549.2.7": "sha1",  # id-hmacWithSHA1, RFC 8018 sec. B.1.1 (what OpenSSL writes)
    "1.2.840.113549.2.8": "sha224",  # id-hmacWithSHA224, RFC 9481 sec. 6.2.1
    "1.2.840.113549.2.9": "sha256",  # id-hmacWithSHA256, RFC 9045 sec. 4.4
    "1.2.840.113549.2.10": "sha384",
    "1.2.840.113549.2.11": "sha512",
}


ID_AES128_GMAC = "2.16.840.1.101.3.4.1.9"  # RFC 9481 sec. 6.2.2
ID_AES192_GMAC = "2.16.840.1.101.3.4.1.29"
ID_AES256_GMAC = "2.16.840.1.101.3.4.1.49"
_GMAC_KEY_OCTETS = {ID_AES128_GMAC: 16, ID_AES192_GMAC: 24, ID_AES256_GMAC: 32}
_GMAC_DEFAULT_LENGTH = 12  # GMACParameters.length DEFAULT 12 (RFC 9045 sec. 4.4)
_GMAC_MIN_LENGTH = 12
_GMAC_TAG_OCTETS = 16  # CRMF and CMP use the maximum, 16 octets (RFC 9045 sec. 4.4 para 15)
_GMAC_NONCE_MIN = 8  # the range the ``cryptography`` AES-GCM accepts is 8 to 128 octets
_GMAC_NONCE_MAX = 128

KEY_RFC9810 = "rfc9810"
"""The PBM key rule of RFC 9810 sec. 5.1.3.1: take the first K octets, or expand when K > H."""
KEY_BASEKEY = "basekey"
"""The whole BASEKEY is the HMAC key, with no truncation or expansion: what OpenSSL 3.5 does."""
_KEY_RULES = (KEY_RFC9810, KEY_BASEKEY)


class PbmError(Exception):
    """PBMParameter is malformed, unsupported or outside policy."""


@dataclass(frozen=True, slots=True)
class PbmParameter:
    """PBMParameter (RFC 4211 sec. 4.4): the salt, OWF and MAC OIDs and the iteration count."""

    salt: bytes
    owf: str
    iterations: int
    mac: str
    mac_nonce: bytes | None = None
    """The GMACParameters nonce, required when ``mac`` is an AES-GMAC OID (RFC 9045 sec. 4.4)."""

    def __post_init__(self) -> None:
        if self.owf not in _OWF:
            raise PbmError(f"unsupported one-way function {self.owf}")
        if self.mac not in _MAC and self.mac not in _GMAC_KEY_OCTETS:
            raise PbmError(f"unsupported MAC algorithm {self.mac}")
        if (self.mac in _GMAC_KEY_OCTETS) != (self.mac_nonce is not None):
            raise PbmError("an AES-GMAC mac needs its nonce, and an HMAC mac has none")
        if self.mac_nonce is not None:
            _check_nonce(self.mac_nonce)
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
    if parameter.mac_nonce is not None:
        # RFC 9045 sec. 4.4: for GMAC the parameters MUST be present, and 16 octets MUST be used
        # for CRMF, so the length is written (it differs from the DEFAULT 12).
        mac = _der.sequence(
            _der.oid(parameter.mac), _gmac_parameters(parameter.mac_nonce, _GMAC_TAG_OCTETS)
        )
    else:
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
        mac_oid = _oid(mac.children[0])
        nonce: bytes | None = None
        if mac_oid in _GMAC_KEY_OCTETS:
            nonce, length = _read_gmac_parameters(
                mac.children[1] if len(mac.children) > 1 else None
            )
            if length != _GMAC_TAG_OCTETS:
                raise PbmError("RFC 9045 sec. 4.4: a GMAC in CRMF MUST use a 16 octet length")
        return PbmParameter(
            salt=salt.payload or b"",
            owf=_oid(owf.children[0]),
            iterations=check_integer(count.payload or b""),
            mac=mac_oid,
            mac_nonce=nonce,
        )
    except (Asn1Error, ValueError, IndexError) as error:
        raise PbmError(f"PBMParameter is malformed: {error}") from error


def pbm_key(secret: bytes, parameter: PbmParameter, *, rule: str = KEY_RFC9810) -> bytes:
    """Derive the MAC key: OWF applied ``iterationCount`` times to ``secret || salt`` (BASEKEY).

    RFC 4211 sec. 4.4 gives the loop. RFC 9810 sec. 5.1.3.1 then says how BASEKEY becomes a K-bit
    key: the most significant K bits when K <= H, and when K > H the MUST-use expansion
    ``BASEKEY || OWF("1" || BASEKEY) || OWF("2" || BASEKEY) ...``. That text does not say what K is
    for HMAC, whose key may be any length. ``rule`` chooses the reading:

    * ``KEY_RFC9810`` (the default): K is the MAC hash's output size, so HMAC-SHA256 over a SHA-1
      OWF expands to 32 octets and HMAC-SHA1 over a SHA-256 OWF takes the first 20;
    * ``KEY_BASEKEY``: the whole BASEKEY keys the HMAC, whatever its size. OpenSSL 3.5.6 does this
      (``tests/test_protection.py::test_pbm_matches_openssl_capture``), so the two disagree
      whenever the OWF and the HMAC hash differ in size.

    An AES-GMAC ``mac`` needs exactly its key size, so it always takes the RFC 9810 rule.
    """
    if rule not in _KEY_RULES:
        raise ValueError(f"rule must be one of {_KEY_RULES}")
    owf = _OWF[parameter.owf]
    key = secret + parameter.salt
    for _ in range(parameter.iterations):
        key = hashlib.new(owf, key).digest()
    if rule == KEY_BASEKEY and parameter.mac in _MAC:
        return key
    want = (
        _GMAC_KEY_OCTETS[parameter.mac]
        if parameter.mac in _GMAC_KEY_OCTETS
        else hashlib.new(_MAC[parameter.mac]).digest_size
    )
    if want <= len(key):
        return key[:want]
    out = key
    counter = 1
    while len(out) < want:
        out += hashlib.new(owf, str(counter).encode("ascii") + key).digest()
        counter += 1
    return out[:want]


def pbm_mac(
    secret: bytes, parameter: PbmParameter, data: bytes, *, rule: str = KEY_RFC9810
) -> bytes:
    """The MAC of ``data`` (the DER ``ProtectedPart``) under the derived key: HMAC, or AES-GMAC."""
    key = pbm_key(secret, parameter, rule=rule)
    if parameter.mac_nonce is not None:
        return _gmac_tag(key, parameter.mac_nonce, data, _GMAC_TAG_OCTETS)
    return hmac.new(key, data, _MAC[parameter.mac]).digest()


def pbm_verify(
    secret: bytes, parameter: PbmParameter, data: bytes, value: bytes, *, rule: str = KEY_RFC9810
) -> bool:
    """Constant-time comparison of a received PKIProtection against the computed MAC."""
    return hmac.compare_digest(pbm_mac(secret, parameter, data, rule=rule), value)


def protected_part(header_der: bytes, body_der: bytes) -> bytes:
    """``ProtectedPart ::= SEQUENCE { header PKIHeader, body PKIBody }`` (RFC 9810 sec. 5.1.3).

    ``body_der`` is the PKIBody TLV, the ``[n]`` alternative, as it travels in the message.
    """
    return _der.sequence(header_der, body_der)


# --------------------------------------------------------------------------------------------
# AES-GMAC (RFC 9044 as used by RFC 9045 sec. 4.4 and RFC 9481 sec. 6.2.2)


def _check_nonce(nonce: bytes) -> None:
    if not _GMAC_NONCE_MIN <= len(nonce) <= _GMAC_NONCE_MAX:
        raise PbmError(
            f"a GMAC nonce here is {_GMAC_NONCE_MIN} to {_GMAC_NONCE_MAX} octets, got {len(nonce)}"
        )


def _gmac_tag(key: bytes, nonce: bytes, data: bytes, length: int) -> bytes:
    """GMAC is AES-GCM over no plaintext with ``data`` as the associated data (NIST SP 800-38D)."""
    try:
        return AESGCM(key).encrypt(nonce, b"", data)[:length]
    except ValueError as error:
        raise PbmError(f"AES-GMAC refused its key or nonce: {error}") from error


def _gmac_parameters(nonce: bytes, length: int) -> bytes:
    """``GMACParameters ::= SEQUENCE { nonce OCTET STRING, length MACLength DEFAULT 12 }``.

    DER omits a field equal to its DEFAULT, so a length of 12 is left out.
    """
    parts = [_der.octet_string(nonce)]
    if length != _GMAC_DEFAULT_LENGTH:
        parts.append(_der.integer(length))
    return _der.sequence(*parts)


def _read_gmac_parameters(node: Node | None) -> tuple[bytes, int]:
    if node is None:
        raise PbmError("RFC 9045 sec. 4.4: GMAC parameters MUST be present")
    items = node.children
    if not 1 <= len(items) <= 2 or items[0].tag.number != _OCTET_STRING:
        raise PbmError("GMACParameters is SEQUENCE { nonce, length OPTIONAL }")
    nonce = items[0].payload or b""
    _check_nonce(nonce)
    length = check_integer(items[1].payload or b"") if len(items) == 2 else _GMAC_DEFAULT_LENGTH
    if not _GMAC_MIN_LENGTH <= length <= _GMAC_TAG_OCTETS:
        raise PbmError("MACLength is 12 to 16 (RFC 9045 sec. 4.4)")
    return nonce, length


@dataclass(frozen=True, slots=True)
class GmacParameter:
    """A protectionAlg of AES-GMAC with a shared key: the algorithm OID, the nonce and the tag length.

    The key is the shared secret itself, exactly 16, 24 or 32 octets for the three OIDs. A nonce
    must never repeat under one key (RFC 9481 sec. 6.2.2 para 2), which is the caller's to ensure:
    ``os.urandom(12)`` for each message is the usual way. GMAC must not be the PRF of PBKDF2.
    """

    algorithm: str
    nonce: bytes
    length: int = _GMAC_TAG_OCTETS

    def __post_init__(self) -> None:
        if self.algorithm not in _GMAC_KEY_OCTETS:
            raise PbmError(f"{self.algorithm} is not an AES-GMAC OID")
        _check_nonce(self.nonce)
        if not _GMAC_MIN_LENGTH <= self.length <= _GMAC_TAG_OCTETS:
            raise PbmError("MACLength is 12 to 16 (RFC 9045 sec. 4.4)")


def gmac_algorithm_identifier(parameter: GmacParameter) -> bytes:
    """``AlgorithmIdentifier { id-aesNNN-GMAC, GMACParameters }`` for the protectionAlg."""
    return _der.sequence(
        _der.oid(parameter.algorithm), _gmac_parameters(parameter.nonce, parameter.length)
    )


def read_gmac_algorithm(algorithm: bytes) -> GmacParameter:
    """Parse a protectionAlg TLV that must be an AES-GMAC identifier."""
    try:
        node, end = decode(algorithm, der=True)
        if end != len(algorithm) or not 1 <= len(node.children) <= _ALG_ITEMS:
            raise PbmError("AlgorithmIdentifier must be SEQUENCE { OID, GMACParameters }")
        oid = _oid(node.children[0])
        params = node.children[1] if len(node.children) == _ALG_ITEMS else None
        nonce, length = _read_gmac_parameters(params)
        return GmacParameter(oid, nonce, length)
    except (Asn1Error, ValueError, IndexError) as error:
        raise PbmError(f"GMAC algorithm identifier is malformed: {error}") from error


def gmac_mac(key: bytes, parameter: GmacParameter, data: bytes) -> bytes:
    """The AES-GMAC tag of ``data`` under the shared ``key``, cut to ``parameter.length``."""
    if len(key) != _GMAC_KEY_OCTETS[parameter.algorithm]:
        raise PbmError(
            f"{parameter.algorithm} needs a {_GMAC_KEY_OCTETS[parameter.algorithm]} octet key"
        )
    return _gmac_tag(key, parameter.nonce, data, parameter.length)


def gmac_verify(key: bytes, parameter: GmacParameter, data: bytes, value: bytes) -> bool:
    """Constant-time comparison of a received PKIProtection against the computed GMAC."""
    return hmac.compare_digest(gmac_mac(key, parameter, data), value)


# --------------------------------------------------------------------------------------------
# PBMAC1 (RFC 8018 sec. 7.1 and appendix A.5, named by RFC 9481 sec. 6.1.2)

ID_PBMAC1 = "1.2.840.113549.1.5.14"
_ID_PBKDF2 = "1.2.840.113549.1.5.12"
_PBMAC1_ITEMS = 2
_PBKDF2_PRF_DEFAULT = "1.2.840.113549.2.7"  # algid-hmacWithSHA1, the DEFAULT of PBKDF2-params.prf
_HMAC_HASH = {
    "1.2.840.113549.2.7": "sha1",
    "1.2.840.113549.2.8": "sha224",
    "1.2.840.113549.2.9": "sha256",
    "1.2.840.113549.2.10": "sha384",
    "1.2.840.113549.2.11": "sha512",
}  # id-hmacWithSHAn, RFC 8018 sec. B.1 and RFC 9481 sec. 6.2.1


@dataclass(frozen=True, slots=True)
class Pbmac1Parameter:
    """PBMAC1-params with PBKDF2 as the KDF and an HMAC as the message authentication scheme.

    ``prf`` is the PBKDF2 pseudorandom function and ``mac`` the HMAC, both id-hmacWithSHAn OIDs.
    ``key_length`` is PBKDF2's keyLength, the octets of derived key. RFC 8018 makes it optional,
    but with an HMAC it decides the key and the RFCs name no default, so this library requires it
    on both sides (RFC 9579 sec. 5, written for PKCS #12, reasons the same way). The salt is the
    ``specified`` octet string; ``otherSource`` is not supported.
    """

    salt: bytes
    iterations: int
    key_length: int
    prf: str
    mac: str

    def __post_init__(self) -> None:
        if self.prf not in _HMAC_HASH or self.mac not in _HMAC_HASH:
            raise PbmError("PBMAC1 here takes HMAC (id-hmacWithSHAn) for the PRF and the MAC")
        if not 1 <= self.iterations <= MAX_ITERATIONS:
            raise PbmError(f"iterationCount {self.iterations} is outside 1..{MAX_ITERATIONS}")
        if self.key_length < 1:
            raise PbmError("keyLength is 1..MAX")
        if not self.salt:
            raise PbmError("the PBKDF2 salt is empty")


def pbmac1_algorithm_identifier(parameter: Pbmac1Parameter) -> bytes:
    """The protectionAlg for id-PBMAC1 with these parameters (RFC 8018 appendix A.2 and A.5).

    The PRF is left out when it is the DEFAULT, id-hmacWithSHA1, because DER omits a default.
    Every HMAC identifier carries NULL parameters (RFC 8018 appendix B.1, RFC 9045 sec. 4.4).
    """
    kdf_items = [
        _der.octet_string(parameter.salt),
        _der.integer(parameter.iterations),
        _der.integer(parameter.key_length),
    ]
    if parameter.prf != _PBKDF2_PRF_DEFAULT:
        kdf_items.append(_der.sequence(_der.oid(parameter.prf), _der.null()))
    kdf = _der.sequence(_der.oid(_ID_PBKDF2), _der.sequence(*kdf_items))
    scheme = _der.sequence(_der.oid(parameter.mac), _der.null())
    return _der.sequence(_der.oid(ID_PBMAC1), _der.sequence(kdf, scheme))


def read_pbmac1_algorithm(algorithm: bytes) -> Pbmac1Parameter:
    """Parse a protectionAlg TLV that must be id-PBMAC1 over PBKDF2 and an HMAC."""
    try:
        node, end = decode(algorithm, der=True)
        if end != len(algorithm) or len(node.children) != _ALG_ITEMS:
            raise PbmError("AlgorithmIdentifier must be SEQUENCE { OID, PBMAC1-params }")
        if _oid(node.children[0]) != ID_PBMAC1:
            raise PbmError("protectionAlg is not id-PBMAC1")
        params = node.children[1]
        if len(params.children) != _PBMAC1_ITEMS:
            raise PbmError("PBMAC1-params is SEQUENCE { keyDerivationFunc, messageAuthScheme }")
        kdf, scheme = params.children
        if _oid(kdf.children[0]) != _ID_PBKDF2:
            raise PbmError("the key derivation function is not PBKDF2")
        items = kdf.children[1].children
        salt, count = items[0], items[1]
        if salt.tag.tag_class is not TagClass.universal or salt.tag.number != _OCTET_STRING:
            raise PbmError("only a specified salt (OCTET STRING) is supported, not otherSource")
        rest = items[2:]
        length = None
        if rest and rest[0].tag.number == 2:
            length = check_integer(rest[0].payload or b"")
            rest = rest[1:]
        if length is None:
            raise PbmError("PBKDF2-params omits keyLength, which this library requires")
        if len(rest) > 1:
            raise PbmError("PBKDF2-params has an unexpected trailing field")
        prf = _oid(rest[0].children[0]) if rest else _PBKDF2_PRF_DEFAULT
        return Pbmac1Parameter(
            salt=salt.payload or b"",
            iterations=check_integer(count.payload or b""),
            key_length=length,
            prf=prf,
            mac=_oid(scheme.children[0]),
        )
    except (Asn1Error, ValueError, IndexError) as error:
        raise PbmError(f"PBMAC1 parameters are malformed: {error}") from error


def pbmac1_key(secret: bytes, parameter: Pbmac1Parameter) -> bytes:
    """``DK = PBKDF2(PRF, secret, salt, iterations, keyLength)`` (RFC 8018 sec. 5.2, 7.1.1 step 3)."""
    return hashlib.pbkdf2_hmac(
        _HMAC_HASH[parameter.prf],
        secret,
        parameter.salt,
        parameter.iterations,
        parameter.key_length,
    )


def pbmac1_mac(secret: bytes, parameter: Pbmac1Parameter, data: bytes) -> bytes:
    """The PBMAC1 value of ``data``: the HMAC of ``messageAuthScheme`` under ``pbmac1_key``."""
    return hmac.new(pbmac1_key(secret, parameter), data, _HMAC_HASH[parameter.mac]).digest()


def pbmac1_verify(secret: bytes, parameter: Pbmac1Parameter, data: bytes, value: bytes) -> bool:
    """Constant-time comparison of a received PKIProtection against the computed PBMAC1."""
    return hmac.compare_digest(pbmac1_mac(secret, parameter, data), value)


# --------------------------------------------------------------------------------------------
# Applying and checking the protection of a whole message (RFC 9810 sec. 5.1.3)


class ProtectionError(Exception):
    """A message's protection is missing, of an unsupported kind, or does not verify."""


def _default_parameter() -> PbmParameter:
    # RFC 9045 sec. 4: SHA-256 is the MUST one-way function and HMAC-SHA256 the MUST MAC, and the
    # iteration count of 10,000 is the advised figure (RFC 9045 sec. 4.3). With K = H both key
    # rules of ``protection.pbm-hmac-key-length`` give the same key, so the default does not
    # depend on that open question.
    return PbmParameter(os.urandom(16), _SHA256_OID, 10_000, _HMAC_SHA256_OID)


def _read_shared_secret_algorithm(
    algorithm: bytes,
) -> PbmParameter | Pbmac1Parameter | GmacParameter:
    try:
        node, _ = decode(algorithm, der=True)
        oid = _oid(node.children[0])
    except (Asn1Error, IndexError) as error:
        raise ProtectionError(f"protectionAlg is malformed: {error}") from error
    try:
        if oid == ID_PASSWORD_BASED_MAC:
            return read_pbm_algorithm(algorithm)
        if oid == ID_PBMAC1:
            return read_pbmac1_algorithm(algorithm)
        if oid in _GMAC_KEY_OCTETS:
            return read_gmac_algorithm(algorithm)
    except PbmError as error:
        raise ProtectionError(str(error)) from error
    raise NotImplementedError(
        f"protectionAlg {oid} is not a shared-secret MAC; signature protection "
        "(RFC 9810 sec. 5.1.3.3) is the protection.signature row"
    )


def protect(
    msg: PkiMessage,
    secret: bytes,
    *,
    parameter: PbmParameter | Pbmac1Parameter | GmacParameter | None = None,
    rule: str = KEY_RFC9810,
) -> PkiMessage:
    """Protect a message with a shared secret and return it protected, RFC 9810 sec. 5.1.3.1.

    The input to the MAC is the DER ``ProtectedPart`` (sec. 5.1.3): the header, with its
    ``protectionAlg`` set to the algorithm used, and the body. So the header is written again
    with that field (sec. 5.1.1: "if protection bits are supplied, then this field MUST be
    supplied") and every other header field kept as it was, then the MAC is computed over the new
    header and the body as it travels and set as the protection. ``extraCerts`` are kept.

    ``parameter`` chooses the algorithm: ``PbmParameter`` (id-PasswordBasedMac), ``Pbmac1Parameter``
    or ``GmacParameter`` (where ``secret`` is the AES key itself). Without it, a protectionAlg the
    header already holds is kept as written and its parameters are used; a header with none gets
    PBM with a fresh 16-octet salt, SHA-256, 10,000 iterations and HMAC-SHA256. ``rule`` is the PBM key rule
    (``pbm_key``). Signature protection (sec. 5.1.3.3) is not done here: see the
    ``protection.signature`` row.
    """
    existing = msg.header.protection_alg
    if parameter is None and existing is not None:
        # keep the algorithm the header already names, byte for byte: encoders differ in whether
        # they write NULL parameters on the OWF and the MAC, and the MAC covers those bytes
        chosen = _read_shared_secret_algorithm(existing)
        algorithm = existing
    else:
        chosen = _default_parameter() if parameter is None else parameter
        if isinstance(chosen, PbmParameter):
            algorithm = pbm_algorithm_identifier(chosen)
        elif isinstance(chosen, Pbmac1Parameter):
            algorithm = pbmac1_algorithm_identifier(chosen)
        elif isinstance(chosen, GmacParameter):
            algorithm = gmac_algorithm_identifier(chosen)
        else:
            raise TypeError("parameter is a PbmParameter, Pbmac1Parameter or GmacParameter")
    header = msg.header
    header_der = build_header(
        pvno=header.pvno,
        sender=header.sender,
        recipient=header.recipient,
        message_time=header.message_time,
        protection_alg=algorithm,
        sender_kid=header.sender_kid,
        recip_kid=header.recip_kid,
        transaction_id=header.transaction_id,
        sender_nonce=header.sender_nonce,
        recip_nonce=header.recip_nonce,
        free_text=header.free_text,
        general_info=header.general_info,
    )
    data = protected_part(header_der, msg.body_raw)
    if isinstance(chosen, PbmParameter):
        value = pbm_mac(secret, chosen, data, rule=rule)
    elif isinstance(chosen, Pbmac1Parameter):
        value = pbmac1_mac(secret, chosen, data)
    else:
        value = gmac_mac(secret, chosen, data)
    parts = [header_der, msg.body_raw, _der.context(0, _der.bit_string(value))]
    if msg.extra_certs:
        parts.append(_der.context(1, _der.sequence(*msg.extra_certs)))
    return parse(_der.sequence(*parts))


def verify_protection(msg: PkiMessage, secret: bytes, *, rule: str = KEY_RFC9810) -> None:
    """Check a message's shared-secret protection, RFC 9810 sec. 5.1.3.1; return if it verifies.

    The MAC is recomputed over the ``ProtectedPart`` made of the header and body bytes that
    arrived (``msg.protected_part``) and compared in constant time with the protection. The
    algorithm is read from ``protectionAlg``: id-PasswordBasedMac (also with an AES-GMAC MAC),
    id-PBMAC1, or an AES-GMAC identifier, where ``secret`` is the AES key. Nothing is tolerated
    that sec. 5.1.1 forbids: protection without ``protectionAlg``, or the reverse, is refused.
    A signature algorithm raises ``NotImplementedError`` (row ``protection.signature``), never a
    silent pass. This does not judge the rest of the header; ``messages.check_header_9483`` does.

    Raises:
        ProtectionError: no protection, a mismatch between protection and protectionAlg, an
            algorithm outside the shared-secret set, parameters outside policy, or a wrong MAC.
        NotImplementedError: a signature-based protectionAlg.
    """
    algorithm = msg.header.protection_alg
    if msg.protection is None:
        raise ProtectionError(
            "the message carries no protection"
            if algorithm is None
            else "protectionAlg is present but the message carries no protection"
        )
    if algorithm is None:
        raise ProtectionError("protection is present but protectionAlg is missing (sec. 5.1.1)")
    parameter = _read_shared_secret_algorithm(algorithm)
    data = msg.protected_part
    if isinstance(parameter, PbmParameter):
        ok = pbm_verify(secret, parameter, data, msg.protection, rule=rule)
    elif isinstance(parameter, Pbmac1Parameter):
        ok = pbmac1_verify(secret, parameter, data, msg.protection)
    else:
        ok = gmac_verify(secret, parameter, data, msg.protection)
    if not ok:
        raise ProtectionError("the protection does not verify under this secret")
