"""CMP PKIMessage and its body variants (RFC 9810, RFC 9811).

``parse_header`` is implemented. Every other object in this module is a placeholder until the
milestone named in ROADMAP.md lands. A stub raises instead of returning a plausible empty value:
a protocol library that silently answers nothing is worse than one that refuses to answer.

The message definitions are ours, written on asn1core. RFC 9810 Appendix F is an
``EXPLICIT TAGS`` module, so every optional ``[n]`` field wraps exactly one value.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from typing import TYPE_CHECKING

from asn1core import (
    Asn1Error,
    Node,
    TagClass,
    check_generalized_time,
    check_integer,
    decode,
)

if TYPE_CHECKING:
    from typing import Any

    CrmfRequest = Any  # placeholder: give it a real type in the milestone that needs it
    PkiMessage = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "CMP_1999",
    "CMP_2000",
    "CMP_2021",
    "HeaderError",
    "MessageError",
    "PkiHeader",
    "build_cr",
    "check_transaction_echo",
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
_INTEGER = 2
_OID = 6
_OCTET_STRING = 4
_UTF8_STRING = 12
_GENERALIZED_TIME = 24


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


def build_cr(request: CrmfRequest, sender: str, recipient: str | None) -> PkiMessage:
    """Pending behaviour defined by RFC 9810 sec. 5.3.3.

    Not implemented yet. See the ``messages.build_cr()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("build_cr() is not implemented: RFC 9810 sec. 5.3.3")


def parse(raw: bytes) -> PkiMessage:
    """Pending behaviour defined by RFC 9810 sec. 5.1.

    Not implemented yet. See the ``messages.parse()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("parse() is not implemented: RFC 9810 sec. 5.1")
