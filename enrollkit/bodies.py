"""CMP message bodies: builders and readers for the contents a client writes and reads (RFC 9810 sec. 5.3).

Each ``*_content`` builder returns the TLV that one PKIBody alternative wraps; hand it to
``messages.build_message(header, "certConf", content)``, which adds the ``[n]`` tag. The readers take a
parsed ``PkiMessage`` and decode its body on demand. Covered here:

* ``ir``, ``cr``, ``kur`` and ``ccr`` bodies, ``CertReqMessages`` (sec. 5.3.1 to 5.3.4, 5.3.7): a
  non-empty ``SEQUENCE OF CertReqMsg``, whose members ``crmf`` builds;
* ``p10cr`` (sec. 5.3.4): a PKCS #10 request carried as is;
* ``certConf`` (sec. 5.3.18) with its ``CertStatus`` and the ``certHash`` rule of sec. 5.3.18 and
  RFC 9481 sec. 3.3;
* ``pollReq`` and ``pollRep`` (sec. 5.3.22);
* ``error`` (sec. 5.3.21), and ``PKIStatusInfo`` (sec. 5.2.3) wherever it appears.

Nothing here chooses a value for the caller: certReqIds, hashes and nonces are arguments, and a
reader reports what arrived without repairing it.
"""

from __future__ import annotations

import hashlib
from collections.abc import Collection, Sequence
from dataclasses import dataclass, field

from asn1core import Asn1Error, Node, Tag, TagClass, check_integer, decode
from asn1core.cert import parse_certificate

from . import _der
from .messages import MessageError, PkiMessage, _free_text

__all__ = [
    "PKI_STATUS_ACCEPTED",
    "PKI_STATUS_GRANTED_WITH_MODS",
    "PKI_STATUS_REJECTION",
    "PKI_STATUS_WAITING",
    "POLL_ALL",
    "CertStatus",
    "ErrorContent",
    "PkiStatusInfo",
    "PollEntry",
    "cert_conf_content",
    "cert_hash",
    "cert_hash_name",
    "cert_req_messages_content",
    "cert_status",
    "error_content",
    "p10cr_content",
    "pki_status_info",
    "poll_rep_content",
    "poll_req_content",
    "read_cert_conf",
    "read_error",
    "read_poll_rep",
    "read_poll_req",
    "read_status_info",
]

# PKIStatus values, RFC 9810 sec. 5.2.3.
PKI_STATUS_ACCEPTED = 0
PKI_STATUS_GRANTED_WITH_MODS = 1
PKI_STATUS_REJECTION = 2
PKI_STATUS_WAITING = 3

POLL_ALL = -1
"""The certReqId of a pollReq that refers to the complete response (RFC 9810 sec. 5.3.22 item 1)."""

_SEQUENCE = 16
_INTEGER = 2
_OCTET_STRING = 4
_BIT_STRING = 3
_CERT_STATUS_HASH_ALG = 0  # CertStatus.hashAlg [0], RFC 9810 sec. 5.3.18
_MAX_FAIL_INFO_BIT = 26  # duplicateCertReq, the last named bit (RFC 9810 sec. 5.2.3)
_MAX_ENTRIES = 1024  # a bound on what a reader returns, not a protocol limit
_CERT_STATUS_MIN = 2  # certHash and certReqId

_HASHES = {
    # Signature algorithm OID -> the hash that signs it, and so the certHash hash (sec. 5.3.18 para 3).
    "1.2.840.113549.1.1.14": "sha224",  # sha224WithRSAEncryption, RFC 4055 sec. 5
    "1.2.840.113549.1.1.11": "sha256",  # sha256WithRSAEncryption
    "1.2.840.113549.1.1.12": "sha384",
    "1.2.840.113549.1.1.13": "sha512",
    "1.2.840.10045.4.3.1": "sha224",  # ecdsa-with-SHA224, RFC 5758 sec. 3.2
    "1.2.840.10045.4.3.2": "sha256",
    "1.2.840.10045.4.3.3": "sha384",
    "1.2.840.10045.4.3.4": "sha512",
    "1.3.101.112": "sha512",  # id-Ed25519: SHA-512, RFC 9481 sec. 3.3 para 7
    "1.3.101.113": "shake256",  # id-Ed448: SHAKE256 with d=512 (64 octets), same note
}
_SHAKE256_OCTETS = 64


# --------------------------------------------------------------------------------------------
# PKIStatusInfo (sec. 5.2.3)


@dataclass(frozen=True, slots=True)
class PkiStatusInfo:
    """PKIStatusInfo: the status, the optional free text and the optional failure bits."""

    status: int
    status_string: tuple[str, ...] = ()
    fail_info: frozenset[int] | None = None


def pki_status_info(
    status: int,
    *,
    status_string: Sequence[str] = (),
    fail_info: Collection[int] | None = None,
) -> bytes:
    """Encode ``PKIStatusInfo ::= SEQUENCE { status, statusString OPTIONAL, failInfo OPTIONAL }``.

    ``fail_info`` is the set of PKIFailureInfo bit numbers (``badAlg`` is 0 ... ``duplicateCertReq``
    is 26). A named-bit BIT STRING is DER-encoded without its trailing zero bits (X.690 sec. 11.2.2),
    so ``{1}`` is the two octets ``06 40``. The free text, if any, must have at least one string
    (``PKIFreeText`` is SIZE (1..MAX)).
    """
    if not 0 <= status <= PKI_STATUS_WAITING + 3:
        raise ValueError("PKIStatus is 0 to 6 (RFC 9810 sec. 5.2.3)")
    parts = [_der.integer(status)]
    if status_string:
        parts.append(_der.sequence(*(_der.utf8_string(text) for text in status_string)))
    if fail_info is not None:
        parts.append(_failure_bits(fail_info))
    return _der.sequence(*parts)


def _failure_bits(bits: Collection[int]) -> bytes:
    if any(not 0 <= bit <= _MAX_FAIL_INFO_BIT for bit in bits):
        raise ValueError(f"PKIFailureInfo bits are 0 to {_MAX_FAIL_INFO_BIT}")
    if not bits:
        return _der.tlv(Tag(_BIT_STRING), b"\x00")  # the empty named-bit list: zero bits
    last = max(bits)
    octets = bytearray(last // 8 + 1)
    for bit in bits:
        octets[bit // 8] |= 0x80 >> (bit % 8)
    unused = 7 - last % 8
    return _der.tlv(Tag(_BIT_STRING), bytes([unused]) + bytes(octets))


def read_status_info(node: Node) -> PkiStatusInfo:
    """Read a PKIStatusInfo node (a SEQUENCE); raises ``MessageError`` for anything else."""
    try:
        if node.tag.number != _SEQUENCE or not node.children:
            raise MessageError("PKIStatusInfo must be a non-empty SEQUENCE")
        status = check_integer(node.children[0].payload or b"")
        text: tuple[str, ...] = ()
        bits: frozenset[int] | None = None
        for item in node.children[1:]:
            if item.tag.number == _SEQUENCE and not text:
                text = _free_text(item)
            elif item.tag.number == _BIT_STRING and bits is None:
                bits = _bits(item.payload or b"")
            else:
                raise MessageError("PKIStatusInfo has an unexpected or repeated field")
    except (Asn1Error, ValueError) as error:
        raise MessageError(f"PKIStatusInfo is malformed: {error}") from error
    return PkiStatusInfo(status, text, bits)


def _bits(payload: bytes) -> frozenset[int]:
    if not payload:
        raise MessageError("an empty BIT STRING has no unused-bits octet")
    unused, data = payload[0], payload[1:]
    if unused > 7 or (not data and unused):
        raise MessageError("BIT STRING has an invalid unused-bits octet")
    found = {
        index * 8 + shift
        for index, octet in enumerate(data)
        for shift in range(8)
        if octet & (0x80 >> shift)
    }
    return frozenset(found)


# --------------------------------------------------------------------------------------------
# ir, cr, kur, ccr and p10cr (sec. 5.3.1 to 5.3.4)


def cert_req_messages_content(*cert_req_msgs: bytes) -> bytes:
    """``CertReqMessages ::= SEQUENCE SIZE (1..MAX) OF CertReqMsg`` for an ir, cr, kur or ccr body.

    Each argument is a finished ``CertReqMsg`` TLV (``crmf.cert_req_msg``). The certReqIds inside
    them are the caller's; this checks only that each is a SEQUENCE and that there is at least one.
    """
    if not cert_req_msgs:
        raise ValueError("CertReqMessages needs at least one CertReqMsg (SIZE (1..MAX))")
    for message in cert_req_msgs:
        if not message or message[0] != 0x30:
            raise ValueError("a CertReqMsg is a SEQUENCE")
    return _der.sequence(*cert_req_msgs)


def p10cr_content(certification_request: bytes) -> bytes:
    """The body of a ``p10cr``: the DER PKCS #10 ``CertificationRequest`` itself (sec. 5.3.4).

    Only the outer shape is checked (one DER SEQUENCE and nothing after it); the signature on the
    request is not verified here.
    """
    try:
        node, end = decode(certification_request, der=True)
    except Asn1Error as error:
        raise ValueError(f"not a DER CertificationRequest: {error}") from error
    if end != len(certification_request) or node.tag.number != _SEQUENCE:
        raise ValueError("a CertificationRequest is one DER SEQUENCE")
    return certification_request


# --------------------------------------------------------------------------------------------
# certConf (sec. 5.3.18)


@dataclass(frozen=True, slots=True)
class CertStatus:
    """One CertStatus of a CertConfirmContent, as read."""

    cert_hash: bytes
    cert_req_id: int
    status_info: PkiStatusInfo | None = None
    hash_alg: bytes | None = None
    """The hashAlg AlgorithmIdentifier TLV when present."""


def cert_hash_name(certificate: bytes) -> str:
    """The hash that computes ``certHash`` for ``certificate`` (DER), by its signature algorithm.

    RFC 9810 sec. 5.3.18 para 3: the same hash as the certificate signature uses. The table covers
    the RSA PKCS #1 v1.5 and ECDSA SHA-2 algorithms and the two EdDSA ones (RFC 9481 sec. 3.3 para 7:
    SHA-512 for Ed25519, SHAKE256 with d=512 for Ed448). Any other, including RSASSA-PSS (whose
    hash sits in its parameters) and anything with SHA-1, raises ``ValueError``: pass ``hash_name``
    to ``cert_hash`` and say so with ``hashAlg``.
    """
    try:
        algorithm = ".".join(str(arc) for arc in parse_certificate(certificate).signature_algorithm)
    except Asn1Error as error:
        raise ValueError(f"not a DER certificate: {error}") from error
    if algorithm not in _HASHES:
        raise ValueError(f"no certHash hash is known for the signature algorithm {algorithm}")
    return _HASHES[algorithm]


def cert_hash(certificate: bytes, hash_name: str | None = None) -> bytes:
    """The ``certHash`` of a DER certificate: the hash of its whole encoding (sec. 5.3.18).

    ``hash_name`` is a ``hashlib`` name; omitted, it follows the certificate's signature algorithm
    through ``cert_hash_name``. ``shake256`` yields 64 octets (RFC 9481 sec. 3.3 para 7).
    """
    name = hash_name or cert_hash_name(certificate)
    if name == "shake256":
        return hashlib.shake_256(certificate).digest(_SHAKE256_OCTETS)
    return hashlib.new(name, certificate).digest()


def cert_status(
    cert_hash_value: bytes,
    cert_req_id: int,
    *,
    status_info: bytes | None = None,
    hash_alg: bytes | None = None,
) -> bytes:
    """``CertStatus ::= SEQUENCE { certHash, certReqId, statusInfo OPTIONAL, hashAlg [0] OPTIONAL }``.

    Omitting ``status_info`` (a ``pki_status_info`` TLV) means acceptance (sec. 5.3.18 para 4).
    ``hash_alg`` is a finished AlgorithmIdentifier TLV and is for the exceptional cases of para 3;
    using it needs a certConf header of version cmp2021 (3), which the caller sets.
    """
    parts = [_der.octet_string(cert_hash_value), _der.integer(cert_req_id)]
    if status_info is not None:
        parts.append(status_info)
    if hash_alg is not None:
        parts.append(_der.context(_CERT_STATUS_HASH_ALG, hash_alg))
    return _der.sequence(*parts)


def cert_conf_content(*statuses: bytes) -> bytes:
    """``CertConfirmContent ::= SEQUENCE OF CertStatus``.

    An empty content, a zero-length SEQUENCE, is valid and "indicate[s] rejection of all supplied
    certificates" (sec. 5.3.18 para 5); a certificate with no CertStatus is rejected too.
    """
    return _der.sequence(*statuses)


def _inner(message: PkiMessage, *names: str) -> Node:
    if message.body_name not in names:
        raise MessageError(f"{message.body_name} is not a {'/'.join(names)} body")
    try:
        wrapper, _ = decode(message.body_raw)
        return wrapper.children[0]
    except (Asn1Error, IndexError) as error:
        raise MessageError(f"the {message.body_name} body is malformed: {error}") from error


def read_cert_conf(message: PkiMessage) -> tuple[CertStatus, ...]:
    """The CertStatus entries of a ``certConf`` message (possibly none: reject all).

    Raises:
        MessageError: not a certConf body, or an entry that is not a CertStatus.
    """
    content = _inner(message, "certConf")
    if content.tag.number != _SEQUENCE or len(content.children) > _MAX_ENTRIES:
        raise MessageError("CertConfirmContent must be a SEQUENCE of at most 1024 entries")
    out = []
    try:
        for entry in content.children:
            items = entry.children
            if entry.tag.number != _SEQUENCE or len(items) < _CERT_STATUS_MIN:
                raise MessageError("CertStatus needs certHash and certReqId")
            if items[0].tag.number != _OCTET_STRING or items[1].tag.number != _INTEGER:
                raise MessageError("CertStatus starts with certHash then certReqId")
            info: PkiStatusInfo | None = None
            alg: bytes | None = None
            for extra in items[2:]:
                if (
                    extra.tag.tag_class is TagClass.context
                    and extra.tag.number == 0
                    and alg is None
                ):
                    alg = extra.children[0].raw
                elif extra.tag.number == _SEQUENCE and info is None and alg is None:
                    info = read_status_info(extra)
                else:
                    raise MessageError("CertStatus has an unexpected or repeated field")
            out.append(
                CertStatus(
                    items[0].payload or b"", check_integer(items[1].payload or b""), info, alg
                )
            )
    except (Asn1Error, IndexError, ValueError) as error:
        raise MessageError(f"CertConfirmContent is malformed: {error}") from error
    return tuple(out)


# --------------------------------------------------------------------------------------------
# pollReq and pollRep (sec. 5.3.22)


@dataclass(frozen=True, slots=True)
class PollEntry:
    """One member of a PollRepContent: which request, when to ask again (seconds), and why."""

    cert_req_id: int
    check_after: int
    reason: tuple[str, ...] = field(default=())


def poll_req_content(*cert_req_ids: int) -> bytes:
    """``PollReqContent ::= SEQUENCE OF SEQUENCE { certReqId INTEGER }``.

    Each id MUST be the index of a CertResponse whose status is "waiting", or ``POLL_ALL`` (-1) for
    the complete response (sec. 5.3.22 item 1). At least one id is required here: an empty poll
    names nothing to poll for.
    """
    if not cert_req_ids:
        raise ValueError("a pollReq needs at least one certReqId")
    if any(i < POLL_ALL for i in cert_req_ids):
        raise ValueError("a certReqId in a pollReq is an index or -1")
    return _der.sequence(*(_der.sequence(_der.integer(i)) for i in cert_req_ids))


def poll_rep_content(entries: Sequence[PollEntry]) -> bytes:
    """``PollRepContent ::= SEQUENCE OF SEQUENCE { certReqId, checkAfter, reason PKIFreeText OPTIONAL }``."""
    members = []
    for entry in entries:
        if entry.check_after < 0:
            raise ValueError("checkAfter is a time in seconds and cannot be negative")
        parts = [_der.integer(entry.cert_req_id), _der.integer(entry.check_after)]
        if entry.reason:
            parts.append(_der.sequence(*(_der.utf8_string(text) for text in entry.reason)))
        members.append(_der.sequence(*parts))
    return _der.sequence(*members)


def read_poll_req(message: PkiMessage) -> tuple[int, ...]:
    """The certReqIds of a ``pollReq`` message, in order."""
    content = _inner(message, "pollReq")
    try:
        if content.tag.number != _SEQUENCE or len(content.children) > _MAX_ENTRIES:
            raise MessageError("PollReqContent must be a SEQUENCE")
        ids = []
        for entry in content.children:
            if entry.tag.number != _SEQUENCE or len(entry.children) != 1:
                raise MessageError("a PollReqContent member is SEQUENCE { certReqId }")
            ids.append(check_integer(entry.children[0].payload or b""))
    except (Asn1Error, ValueError) as error:
        raise MessageError(f"PollReqContent is malformed: {error}") from error
    return tuple(ids)


def read_poll_rep(message: PkiMessage) -> tuple[PollEntry, ...]:
    """The entries of a ``pollRep`` message, in order."""
    content = _inner(message, "pollRep")
    try:
        if content.tag.number != _SEQUENCE or len(content.children) > _MAX_ENTRIES:
            raise MessageError("PollRepContent must be a SEQUENCE")
        out = []
        for entry in content.children:
            items = entry.children
            if entry.tag.number != _SEQUENCE or not 2 <= len(items) <= 3:
                raise MessageError("a PollRepContent member is certReqId, checkAfter, reason?")
            wait = check_integer(items[1].payload or b"")
            if wait < 0:
                raise MessageError("checkAfter is negative")
            reason = _free_text(items[2]) if len(items) == 3 else ()
            out.append(PollEntry(check_integer(items[0].payload or b""), wait, reason))
    except (Asn1Error, ValueError) as error:
        raise MessageError(f"PollRepContent is malformed: {error}") from error
    return tuple(out)


# --------------------------------------------------------------------------------------------
# error (sec. 5.3.21)


@dataclass(frozen=True, slots=True)
class ErrorContent:
    """ErrorMsgContent: the status info, the optional error code and the optional details."""

    status_info: PkiStatusInfo
    error_code: int | None = None
    error_details: tuple[str, ...] = ()


def error_content(
    status_info: bytes, *, error_code: int | None = None, error_details: Sequence[str] = ()
) -> bytes:
    """``ErrorMsgContent ::= SEQUENCE { pKIStatusInfo, errorCode INTEGER OPTIONAL, errorDetails OPTIONAL }``."""
    parts = [status_info]
    if error_code is not None:
        parts.append(_der.integer(error_code))
    if error_details:
        parts.append(_der.sequence(*(_der.utf8_string(text) for text in error_details)))
    return _der.sequence(*parts)


def read_error(message: PkiMessage) -> ErrorContent:
    """Read an ``error`` message (sec. 5.3.21): its status, code and details.

    Raises:
        MessageError: not an error body, or malformed.
    """
    content = _inner(message, "error")
    try:
        if content.tag.number != _SEQUENCE or not content.children:
            raise MessageError("ErrorMsgContent must be a non-empty SEQUENCE")
        info = read_status_info(content.children[0])
        code: int | None = None
        details: tuple[str, ...] = ()
        for item in content.children[1:]:
            if item.tag.number == _INTEGER and code is None and not details:
                code = check_integer(item.payload or b"")
            elif item.tag.number == _SEQUENCE and not details:
                details = _free_text(item)
            else:
                raise MessageError("ErrorMsgContent has an unexpected or repeated field")
    except (Asn1Error, ValueError) as error:
        raise MessageError(f"ErrorMsgContent is malformed: {error}") from error
    return ErrorContent(info, code, details)
