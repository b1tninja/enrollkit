"""CMP PKIMessage and its body variants (RFC 9810, RFC 9811).

``parse_header`` is implemented. Every other object in this module is a placeholder until the
milestone named in ROADMAP.md lands. A stub raises instead of returning a plausible empty value:
a protocol library that silently answers nothing is worse than one that refuses to answer.

The message definitions are ours, written on asn1core. RFC 9810 Appendix F is an
``EXPLICIT TAGS`` module, so every optional ``[n]`` field wraps exactly one value.
"""

from __future__ import annotations

import datetime
import secrets
from collections.abc import Sequence
from dataclasses import dataclass

from asn1core import (
    Asn1Error,
    Node,
    TagClass,
    check_generalized_time,
    check_integer,
    decode,
    decode_oid,
)

from . import _der

__all__ = [
    "CMP_1999",
    "CMP_2000",
    "CMP_2021",
    "CertResponse",
    "HeaderError",
    "MessageError",
    "PkiHeader",
    "PkiMessage",
    "body_name",
    "build_cr",
    "build_header",
    "build_message",
    "cert_responses",
    "check_header_9483",
    "check_transaction_echo",
    "directory_name_cn",
    "general_info_cert_profile",
    "general_info_confirm_wait_time",
    "general_info_implicit_confirm",
    "is_null_dn",
    "parse",
    "parse_header",
]

# PKIHeader.pvno values, RFC 9810 sec. 5.1.1. Section 7 says when each is used; this module only
# names them and never picks one for a caller.
CMP_1999 = 1
CMP_2000 = 2
CMP_2021 = 3
_VERSION_NAMES = {CMP_1999: "cmp1999", CMP_2000: "cmp2000", CMP_2021: "cmp2021"}

# RFC 9810 sec. 5.1.1 says a senderNonce is "typically 128 bits" and recommends 128 bits for a
# transactionID. Neither is a minimum the receiver must enforce, so a shorter value is reported
# (PkiHeader.short_nonces) and never refused.
RECOMMENDED_NONCE_BYTES = 16

# Policy bounds, not protocol limits: the RFC sets no size on these fields, and a parser fed from
# the network needs one. Chosen well above anything a real CA sends.
MAX_FIELD_BYTES = 4096
MAX_FREE_TEXT_ITEMS = 32
MAX_FREE_TEXT_BYTES = 4096
MAX_GENERAL_INFO_ITEMS = 64

# GeneralName is a CHOICE of [0]..[8] (RFC 5280 sec. 4.2.1.6); directoryName is [4].
_GENERAL_NAME_LAST = 8
_LAST_FIELD = 8  # generalInfo, the last field of PKIHeader
_DIRECTORY_NAME = 4
_NULL_DN = bytes.fromhex("a4023000")  # RFC 9810 sec. 5.1.1: an empty RDNSequence, 0x3000, in [4]

_SEQUENCE = 16
_SEQUENCE_BYTE = 0x30  # the identifier octet of a universal constructed SEQUENCE
_INTEGER = 2
_OID = 6
_OCTET_STRING = 4
_UTF8_STRING = 12
_GENERALIZED_TIME = 24
_BIT_STRING = 3


class MessageError(Exception):
    """A CMP message is malformed or breaks a rule of RFC 9810."""


class HeaderError(MessageError):
    """A PKIHeader is malformed or breaks a rule of RFC 9810 sec. 5.1.1."""


@dataclass(frozen=True, slots=True)
class PkiHeader:
    """A parsed PKIHeader (RFC 9810 sec. 5.1.1).

    ``sender``, ``recipient``, ``protection_alg`` and each ``general_info`` item hold the TLV
    exactly as received, so protection can later be checked over the bytes that arrived. An
    optional field that was absent is ``None`` (``free_text`` and ``general_info`` are empty
    tuples, because the ASN.1 forbids an empty sequence there); a present-but-empty
    OCTET STRING stays ``b""`` and is never confused with absence.
    """

    pvno: int
    sender: bytes
    recipient: bytes
    message_time: datetime.datetime | None = None
    protection_alg: bytes | None = None
    sender_kid: bytes | None = None
    recip_kid: bytes | None = None
    transaction_id: bytes | None = None
    sender_nonce: bytes | None = None
    recip_nonce: bytes | None = None
    free_text: tuple[str, ...] = ()
    general_info: tuple[bytes, ...] = ()

    @property
    def version_name(self) -> str | None:
        """``cmp1999``, ``cmp2000`` or ``cmp2021``; ``None`` for a value RFC 9810 does not name."""
        return _VERSION_NAMES.get(self.pvno)

    def short_nonces(self) -> tuple[str, ...]:
        """Names of the nonce-like fields present but shorter than the recommended 128 bits."""
        fields = (
            ("transaction_id", self.transaction_id),
            ("sender_nonce", self.sender_nonce),
            ("recip_nonce", self.recip_nonce),
        )
        return tuple(
            name
            for name, value in fields
            if value is not None and len(value) < RECOMMENDED_NONCE_BYTES
        )


def is_null_dn(general_name: bytes) -> bool:
    """True when this stored GeneralName is the NULL-DN of RFC 9810 sec. 5.1.1."""
    return general_name == _NULL_DN


def parse_header(der: bytes) -> PkiHeader:
    """Parse one DER PKIHeader (RFC 9810 sec. 5.1.1) and nothing after it.

    The module is ``EXPLICIT TAGS`` (RFC 9810 Appendix F), so every optional field is a
    constructed ``[n]`` wrapping exactly one value. Fields are found by tag, and a field out of
    order, repeated, or tagged outside ``[0]..[8]`` is refused. Unknown ``pvno`` values parse and
    are reported through ``version_name``; answering them is RFC 9810 sec. 7's business.

    Raises:
        HeaderError: the bytes are not a conforming PKIHeader.
    """
    try:
        root, end = decode(der, der=True)
    except Asn1Error as error:
        raise HeaderError(f"PKIHeader is not valid DER: {error}") from error
    if end != len(der):
        raise HeaderError(f"{len(der) - end} octets follow the PKIHeader")
    try:
        return _header(root)
    except Asn1Error as error:
        raise HeaderError(f"PKIHeader field is malformed: {error}") from error


def check_transaction_echo(request: PkiHeader, response: PkiHeader) -> None:
    """Enforce RFC 9810 sec. 5.1.1: a server MUST echo a transactionID the request carried.

    Raises:
        HeaderError: the request set a transactionID and the response differs or omits it.
    """
    if request.transaction_id is not None and response.transaction_id != request.transaction_id:
        raise HeaderError("response does not echo the request's transactionID")


def _universal(node: Node, number: int, what: str, *, constructed: bool) -> None:
    tag = node.tag
    if tag.tag_class is not TagClass.universal or tag.number != number:
        raise HeaderError(f"{what} must be universal tag {number}")
    if tag.constructed is not constructed:
        raise HeaderError(f"{what} has the wrong primitive/constructed form")


def _octets(node: Node, what: str) -> bytes:
    _universal(node, _OCTET_STRING, what, constructed=False)
    value = node.payload or b""
    if len(value) > MAX_FIELD_BYTES:
        raise HeaderError(f"{what} is {len(value)} octets, over the {MAX_FIELD_BYTES} bound")
    return value


def _general_name(node: Node, what: str) -> bytes:
    tag = node.tag
    if tag.tag_class is not TagClass.context or tag.number > _GENERAL_NAME_LAST:
        raise HeaderError(f"{what} is not a GeneralName: its tag is outside [0]..[8]")
    if tag.number == _DIRECTORY_NAME:
        if not tag.constructed or len(node.children) != 1:
            raise HeaderError(f"{what} directoryName must wrap exactly one Name")
        _universal(node.children[0], _SEQUENCE, what + " Name", constructed=True)
    return node.raw


def _header(root: Node) -> PkiHeader:
    _universal(root, _SEQUENCE, "PKIHeader", constructed=True)
    items = root.children
    if len(items) < 3:
        raise HeaderError("PKIHeader needs pvno, sender and recipient")
    _universal(items[0], _INTEGER, "pvno", constructed=False)
    pvno = check_integer(items[0].payload or b"")
    sender = _general_name(items[1], "sender")
    recipient = _general_name(items[2], "recipient")

    fields: dict[int, Node] = {}
    previous = -1
    for item in items[3:]:
        tag = item.tag
        if tag.tag_class is not TagClass.context or tag.number > _LAST_FIELD:
            raise HeaderError("PKIHeader has a field outside [0]..[8]")
        if tag.number <= previous:
            raise HeaderError(f"PKIHeader field [{tag.number}] is repeated or out of order")
        if not tag.constructed or len(item.children) != 1:
            raise HeaderError(f"PKIHeader field [{tag.number}] must wrap exactly one value")
        previous = tag.number
        fields[tag.number] = item.children[0]

    message_time = None
    if (node := fields.get(0)) is not None:
        _universal(node, _GENERALIZED_TIME, "messageTime", constructed=False)
        message_time = check_generalized_time(node.payload or b"")
    protection_alg = None
    if (node := fields.get(1)) is not None:
        _universal(node, _SEQUENCE, "protectionAlg", constructed=True)
        protection_alg = node.raw
    octet_fields = {
        number: _octets(node, name)
        for number, name in (
            (2, "senderKID"),
            (3, "recipKID"),
            (4, "transactionID"),
            (5, "senderNonce"),
            (6, "recipNonce"),
        )
        if (node := fields.get(number)) is not None
    }
    return PkiHeader(
        pvno=pvno,
        sender=sender,
        recipient=recipient,
        message_time=message_time,
        protection_alg=protection_alg,
        sender_kid=octet_fields.get(2),
        recip_kid=octet_fields.get(3),
        transaction_id=octet_fields.get(4),
        sender_nonce=octet_fields.get(5),
        recip_nonce=octet_fields.get(6),
        free_text=_free_text(fields[7]) if 7 in fields else (),
        general_info=_general_info(fields[8]) if 8 in fields else (),
    )


def _free_text(node: Node) -> tuple[str, ...]:
    _universal(node, _SEQUENCE, "freeText", constructed=True)
    if not node.children:
        raise HeaderError("freeText is SIZE (1..MAX) and may not be empty")
    if len(node.children) > MAX_FREE_TEXT_ITEMS:
        raise HeaderError(f"freeText has more than {MAX_FREE_TEXT_ITEMS} items")
    texts = []
    total = 0
    for child in node.children:
        _universal(child, _UTF8_STRING, "freeText item", constructed=False)
        raw = child.payload or b""
        total += len(raw)
        if total > MAX_FREE_TEXT_BYTES:
            raise HeaderError(f"freeText exceeds {MAX_FREE_TEXT_BYTES} octets")
        try:
            texts.append(raw.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise HeaderError("freeText item is not valid UTF-8") from error
    return tuple(texts)


def _general_info(node: Node) -> tuple[bytes, ...]:
    _universal(node, _SEQUENCE, "generalInfo", constructed=True)
    if not node.children:
        raise HeaderError("generalInfo is SIZE (1..MAX) and may not be empty")
    if len(node.children) > MAX_GENERAL_INFO_ITEMS:
        raise HeaderError(f"generalInfo has more than {MAX_GENERAL_INFO_ITEMS} items")
    for child in node.children:
        _universal(child, _SEQUENCE, "InfoTypeAndValue", constructed=True)
        if not child.children:
            raise HeaderError("InfoTypeAndValue must begin with an OBJECT IDENTIFIER")
        _universal(child.children[0], _OID, "infoType", constructed=False)
        if len(child.children) > 2:
            raise HeaderError("InfoTypeAndValue has more than infoType and infoValue")
    return tuple(child.raw for child in node.children)


def build_cr(
    request: bytes,
    sender: str,
    recipient: str | None,
    *,
    pvno: int = CMP_2000,
    message_time: datetime.datetime | None = None,
    transaction_id: bytes | None = None,
    sender_nonce: bytes | None = None,
    implicit_confirm: bool = False,
    cert_profile: Sequence[str] = (),
) -> PkiMessage:
    """A Certification Request message (``cr``) around a CertReqMessages, RFC 9810 sec. 5.3.3.

    ``request`` is the ``CertReqMessages`` value (``bodies.cert_req_messages_content``). The body
    is the ``[2]`` alternative that wraps it. The header follows the RFC 9483 sec. 3.1 rules for
    a MAC-protected request: ``sender`` is the name the PKI management entity uses to find the
    shared secret, written as a directoryName with that commonName and repeated as senderKID;
    ``recipient`` is the commonName of the CA, or the NULL-DN when ``None`` (sec. 3.1: "the
    NULL-DN MUST be used" when the recipient is not known). ``transaction_id`` and ``sender_nonce``
    are 128 random bits each unless given (so a test can fix them). ``pvno`` defaults to cmp2000,
    which sec. 3.1 asks for unless EnvelopedData is expected. ``implicit_confirm`` and
    ``cert_profile`` add those generalInfo items.

    The message is not protected: it has no protectionAlg and no protection. Hand it to
    ``protection.protect``, which adds both. A request that will be signed instead needs a header
    from ``build_header`` with the protection certificate's subject, which a string cannot express.

    Raises:
        ValueError: ``request`` is not a DER SEQUENCE, or ``sender`` is empty.
    """
    if not request or request[0] != _SEQUENCE_BYTE:
        raise ValueError("a CertReqMessages is a DER SEQUENCE")
    if not sender:
        raise ValueError("the sender name is empty")
    info = []
    if implicit_confirm:
        info.append(general_info_implicit_confirm())
    if cert_profile:
        info.append(general_info_cert_profile(*cert_profile))
    header = build_header(
        pvno=pvno,
        sender=directory_name_cn(sender),
        recipient=_NULL_DN if recipient is None else directory_name_cn(recipient),
        message_time=message_time,
        sender_kid=sender.encode("utf-8"),
        transaction_id=secrets.token_bytes(RECOMMENDED_NONCE_BYTES)
        if transaction_id is None
        else transaction_id,
        sender_nonce=secrets.token_bytes(RECOMMENDED_NONCE_BYTES)
        if sender_nonce is None
        else sender_nonce,
        general_info=info,
    )
    return parse(build_message(header, "cr", request))


# --------------------------------------------------------------------------------------------
# Building a PKIHeader, and the RFC 9483 sec. 3.1 profile rules.

_ID_IT = "1.3.6.1.5.5.7.4"  # RFC 9810 Appendix F: id-it ::= {id-pkix 4}
ID_IT_IMPLICIT_CONFIRM = _ID_IT + ".13"  # RFC 9810 sec. 5.1.1.1
ID_IT_CONFIRM_WAIT_TIME = _ID_IT + ".14"  # RFC 9810 sec. 5.1.1.2
ID_IT_CERT_PROFILE = _ID_IT + ".21"  # RFC 9810 sec. 5.1.1.4, added by RFC 9480
_ID_AT_COMMON_NAME = "2.5.4.3"

# PKIBody CHOICE alternatives, RFC 9810 sec. 5.1.2, by tag number.
BODY_NAMES = (
    "ir", "ip", "cr", "cp", "p10cr", "popdecc", "popdecr", "kur", "kup", "krr", "krp", "rr",
    "rp", "ccr", "ccp", "ckuann", "cann", "rann", "crlann", "pkiconf", "nested", "genm", "genp",
    "error", "certConf", "pollReq", "pollRep",
)  # fmt: skip

_REQUESTS = frozenset({"ir", "cr", "kur", "p10cr"})
_RESPONSES = frozenset({"ip", "cp", "kup"})
_SET = _der.Tag(17, True)


def body_name(tag_number: int) -> str:
    """The RFC 9810 sec. 5.1.2 name of PKIBody alternative ``[tag_number]``."""
    if not 0 <= tag_number < len(BODY_NAMES):
        raise MessageError(f"PKIBody has no alternative [{tag_number}]")
    return BODY_NAMES[tag_number]


def directory_name_cn(common_name: str) -> bytes:
    """A GeneralName directoryName ``[4]`` whose Name holds one commonName.

    RFC 9483 sec. 3.1 requires this shape for the sender of a MAC-protected message.
    """
    attribute = _der.sequence(_der.oid(_ID_AT_COMMON_NAME), _der.utf8_string(common_name))
    name = _der.sequence(_der.tlv(_SET, attribute))
    return _der.context(_DIRECTORY_NAME, name)


def _info(oid: str, value: bytes | None = None) -> bytes:
    return _der.sequence(_der.oid(oid), *((value,) if value is not None else ()))


def general_info_implicit_confirm() -> bytes:
    """InfoTypeAndValue for implicitConfirm: its value is NULL (RFC 9810 sec. 5.1.1.1)."""
    return _info(ID_IT_IMPLICIT_CONFIRM, _der.null())


def general_info_confirm_wait_time(until: datetime.datetime) -> bytes:
    """InfoTypeAndValue for confirmWaitTime: a GeneralizedTime (RFC 9810 sec. 5.1.1.2)."""
    return _info(ID_IT_CONFIRM_WAIT_TIME, _der.generalized_time(until))


def general_info_cert_profile(*names: str) -> bytes:
    """InfoTypeAndValue for certProfile: a SEQUENCE of UTF8String (RFC 9483 sec. 3.1)."""
    if not names:
        raise ValueError("certProfile must name at least one profile")
    return _info(ID_IT_CERT_PROFILE, _der.sequence(*(_der.utf8_string(n) for n in names)))


def build_header(
    *,
    pvno: int,
    sender: bytes,
    recipient: bytes,
    message_time: datetime.datetime | None = None,
    protection_alg: bytes | None = None,
    sender_kid: bytes | None = None,
    recip_kid: bytes | None = None,
    transaction_id: bytes | None = None,
    sender_nonce: bytes | None = None,
    recip_nonce: bytes | None = None,
    free_text: Sequence[str] = (),
    general_info: Sequence[bytes] = (),
) -> bytes:
    """Encode a PKIHeader (RFC 9810 sec. 5.1.1) in DER; the inverse of ``parse_header``.

    ``sender``, ``recipient``, ``protection_alg`` and each ``general_info`` item are finished TLVs
    (the form ``PkiHeader`` stores them in). Optional fields are written in tag order, each as an
    EXPLICIT ``[n]`` (Appendix F is an ``EXPLICIT TAGS`` module). Nothing here picks a value for
    the caller: choosing a pvno or generating a nonce is the caller's decision, and
    ``check_header_9483`` judges the result.
    """
    parts = [_der.integer(pvno), sender, recipient]
    if message_time is not None:
        parts.append(_der.context(0, _der.generalized_time(message_time)))
    if protection_alg is not None:
        parts.append(_der.context(1, protection_alg))
    octet_fields = (
        (2, sender_kid),
        (3, recip_kid),
        (4, transaction_id),
        (5, sender_nonce),
        (6, recip_nonce),
    )
    for number, value in octet_fields:
        if value is not None:
            parts.append(_der.context(number, _der.octet_string(value)))
    if free_text:
        parts.append(_der.context(7, _der.sequence(*(_der.utf8_string(t) for t in free_text))))
    if general_info:
        parts.append(_der.context(8, _der.sequence(*general_info)))
    return _der.sequence(*parts)


def _oid_text(node: Node) -> str:
    return ".".join(str(arc) for arc in decode_oid(node.payload or b""))


def _general_info_values(header: PkiHeader) -> dict[str, Node]:
    found: dict[str, Node] = {}
    for item in header.general_info:
        node, _ = decode(item)
        oid = _oid_text(node.children[0])
        if oid in found:
            raise HeaderError(f"generalInfo repeats infoType {oid}")
        found[oid] = node.children[1] if len(node.children) > 1 else node
    return found


def _sender_common_name(sender: bytes) -> bytes | None:
    try:
        node, _ = decode(sender)
        if node.tag.number != _DIRECTORY_NAME:
            return None
        for rdn in node.children[0].children:
            for atv in rdn.children:
                if _oid_text(atv.children[0]) == _ID_AT_COMMON_NAME:
                    return atv.children[1].payload or b""
    except (Asn1Error, IndexError):
        return None
    return None


def check_header_9483(
    header: PkiHeader,
    body: str,
    *,
    first_message: bool,
    previous: PkiHeader | None = None,
    protection: str = "signature",
    protection_cert_ski: bytes | None = None,
    enveloped_data: bool = False,
    cert_conf_hash_alg: bool = False,
    delayed_response: bool = False,
) -> tuple[str, ...]:
    """Return every RFC 9483 sec. 3.1 rule this header breaks; empty means it conforms.

    ``body`` is the PKIBody name (``ir``, ``certConf``, ...). ``previous`` is the previous message
    of the same transaction, required unless ``first_message``. ``protection`` is ``"signature"``
    or ``"mac"``; for a signature, ``protection_cert_ski`` is the SubjectKeyIdentifier of the
    protection certificate when it has one. RFC 9483 cites RFC 9480 for version negotiation; that
    maps to RFC 9810 sec. 7 now (RFC 9480 is obsoleted by RFC 9810 and RFC 9811). Rules that need
    the protection certificate's subject are the caller's to check.
    """
    problems: list[str] = []
    if not first_message and previous is None:
        raise ValueError("previous is required when first_message is false")
    wants_v3 = enveloped_data or (body == "certConf" and cert_conf_hash_alg)
    want = CMP_2021 if wants_v3 else CMP_2000
    if header.pvno != want:
        problems.append(f"pvno must be {want}, got {header.pvno}")
    if header.protection_alg is None:
        problems.append("protectionAlg is REQUIRED")
    if header.transaction_id is None:
        problems.append("transactionID is REQUIRED")
    elif first_message and len(header.transaction_id) != RECOMMENDED_NONCE_BYTES:
        problems.append("transactionID of the first message must be 128 bits")
    elif previous is not None and header.transaction_id != previous.transaction_id:
        problems.append("transactionID must equal the previous message's")
    if header.sender_nonce is None:
        problems.append("senderNonce is REQUIRED")
    elif len(header.sender_nonce) != RECOMMENDED_NONCE_BYTES:
        problems.append("senderNonce must be 128 bits")
    if first_message:
        if header.recip_nonce is not None:
            problems.append("recipNonce must be absent in the first message")
    elif previous is not None and header.recip_nonce != previous.sender_nonce:
        which = "delayed response" if delayed_response else "message"
        problems.append(f"recipNonce of a {which} must equal the previous senderNonce")
    if protection == "mac":
        cn = _sender_common_name(header.sender)
        if cn is None:
            problems.append("MAC protection: sender must be a directoryName with a commonName")
        elif header.sender_kid != cn:
            problems.append("MAC protection: senderKID must equal the sender commonName")
    elif protection_cert_ski is not None and header.sender_kid != protection_cert_ski:
        problems.append("signature protection: senderKID must be the certificate's SKI")
    try:
        info = _general_info_values(header)
    except (HeaderError, Asn1Error) as error:
        return (*problems, f"generalInfo unreadable: {error}")
    if ID_IT_IMPLICIT_CONFIRM in info:
        if body not in _REQUESTS | _RESPONSES:
            problems.append(f"implicitConfirm is PROHIBITED in {body}")
        if info[ID_IT_IMPLICIT_CONFIRM].raw != b"\x05\x00":
            problems.append("ImplicitConfirmValue must be NULL")
        if ID_IT_CONFIRM_WAIT_TIME in info:
            problems.append("confirmWaitTime is PROHIBITED with implicitConfirm")
    if ID_IT_CONFIRM_WAIT_TIME in info:
        if header.message_time is None:
            problems.append("messageTime must be present with confirmWaitTime")
        if info[ID_IT_CONFIRM_WAIT_TIME].tag.number != _GENERALIZED_TIME:
            problems.append("ConfirmWaitTimeValue must be a GeneralizedTime")
    if ID_IT_CERT_PROFILE in info:
        if body not in _REQUESTS | {"genm"}:
            problems.append(f"certProfile must be omitted in {body}")
        value = info[ID_IT_CERT_PROFILE]
        if (
            value.tag.number != _SEQUENCE
            or len(value.children) != 1
            or value.children[0].tag.number != _UTF8_STRING
        ):
            problems.append("CertProfileValue must be a sequence of one UTF8String")
    return tuple(problems)


# --------------------------------------------------------------------------------------------
# PKIMessage: header, body alternative, protection and extraCerts (RFC 9810 sec. 5.1).


@dataclass(frozen=True, slots=True)
class PkiMessage:
    """A parsed PKIMessage. ``body`` is the inner value of the ``[n]`` alternative, as received.

    ``protected_part`` is the DER of ``ProtectedPart ::= SEQUENCE { header, body }`` rebuilt from
    the received header and body TLVs, the input of the protection (RFC 9810 sec. 5.1.3).
    """

    header: PkiHeader
    header_raw: bytes
    body_tag: int
    body_raw: bytes
    protection: bytes | None
    extra_certs: tuple[bytes, ...]

    @property
    def body_name(self) -> str:
        return body_name(self.body_tag)

    @property
    def protected_part(self) -> bytes:
        return _der.sequence(self.header_raw, self.body_raw)


def parse(raw: bytes) -> PkiMessage:
    """Parse one DER PKIMessage (RFC 9810 sec. 5.1) into header, body alternative and protection.

    The body is kept as its ``[n]`` TLV, so protection can be checked over the bytes that
    arrived; ``cert_responses`` and the other body readers decode it on demand.

    Raises:
        MessageError: the bytes are not a conforming PKIMessage.
    """
    try:
        root, end = decode(raw, der=True)
    except Asn1Error as error:
        raise MessageError(f"PKIMessage is not valid DER: {error}") from error
    if end != len(raw):
        raise MessageError(f"{len(raw) - end} octets follow the PKIMessage")
    _check_message_shape(root)
    items = root.children
    header_raw = items[0].raw
    header = parse_header(header_raw)
    body = items[1]
    protection = None
    extra: tuple[bytes, ...] = ()
    for item in items[2:]:
        if item.tag.tag_class is not TagClass.context or not item.tag.constructed:
            raise MessageError("PKIMessage has an unexpected trailing field")
        if item.tag.number == 0 and protection is None and not extra:
            if len(item.children) != 1:
                raise MessageError("protection must wrap one BIT STRING")
            protection = item.children[0].payload
            if item.children[0].tag.number != _BIT_STRING or not protection:
                raise MessageError("protection must be a non-empty BIT STRING")
        elif item.tag.number == 1 and not extra:
            if len(item.children) != 1 or item.children[0].tag.number != _SEQUENCE:
                raise MessageError("extraCerts must wrap one SEQUENCE")
            if not item.children[0].children:
                raise MessageError("extraCerts is SIZE (1..MAX) and may not be empty")
            extra = tuple(child.raw for child in item.children[0].children)
        else:
            raise MessageError(f"PKIMessage field [{item.tag.number}] is repeated or unknown")
    return PkiMessage(
        header=header,
        header_raw=header_raw,
        body_tag=body.tag.number,
        body_raw=body.raw,
        protection=protection[1:] if protection else None,
        extra_certs=extra,
    )


def _check_message_shape(root: Node) -> None:
    if root.tag.tag_class is not TagClass.universal or root.tag.number != _SEQUENCE:
        raise MessageError("PKIMessage must be a SEQUENCE")
    if len(root.children) < 2:
        raise MessageError("PKIMessage needs a header and a body")
    body = root.children[1]
    if body.tag.tag_class is not TagClass.context or body.tag.number >= len(BODY_NAMES):
        raise MessageError("PKIBody is not one of the alternatives [0]..[26]")
    if not body.tag.constructed:
        raise MessageError("PKIBody alternative must be constructed (EXPLICIT tag)")


def build_message(
    header_der: bytes,
    body_name_: str,
    body_content: bytes,
    *,
    protection: bytes | None = None,
    extra_certs: Sequence[bytes] = (),
) -> bytes:
    """Encode a PKIMessage from finished parts. ``body_content`` is the TLV the alternative wraps."""
    if body_name_ not in BODY_NAMES:
        raise ValueError(f"unknown PKIBody {body_name_!r}")
    parts = [header_der, _der.context(BODY_NAMES.index(body_name_), body_content)]
    if protection is not None:
        parts.append(_der.context(0, _der.bit_string(protection)))
    if extra_certs:
        parts.append(_der.context(1, _der.sequence(*extra_certs)))
    return _der.sequence(*parts)


@dataclass(frozen=True, slots=True)
class CertResponse:
    """One CertResponse of a CertRepMessage (RFC 9810 sec. 5.3.4): id and PKIStatusInfo."""

    cert_req_id: int
    status: int
    fail_info: bytes | None = None


def cert_responses(message: PkiMessage) -> tuple[CertResponse, ...]:
    """Read the CertResponse list of an ip, cp, kup or ccp body.

    Raises:
        MessageError: the body is another alternative or is malformed.
    """
    if message.body_name not in {"ip", "cp", "kup", "ccp"}:
        raise MessageError(f"{message.body_name} is not a CertRepMessage")
    try:
        wrapper, _ = decode(message.body_raw)
        rep = wrapper.children[0]
        responses = next(
            c for c in rep.children if c.tag.tag_class is TagClass.universal and c.tag.number == 16
        )
        out = []
        for response in responses.children:
            req_id = check_integer(response.children[0].payload or b"")
            info = response.children[1]
            status = check_integer(info.children[0].payload or b"")
            fail = next((c.payload for c in info.children[1:] if c.tag.number == _BIT_STRING), None)
            out.append(CertResponse(req_id, status, fail))
    except (Asn1Error, IndexError, StopIteration) as error:
        raise MessageError(f"CertRepMessage is malformed: {error}") from error
    return tuple(out)
