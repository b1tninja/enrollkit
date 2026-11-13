"""A small DER writer on asn1core's tag, length and OID encoders.

asn1core decodes and re-serialises parsed nodes; it has no builder, so the few constructors this
package needs live here. Every function returns finished TLV bytes.
"""

from __future__ import annotations

import datetime

from asn1core import (
    Tag,
    TagClass,
    encode_generalized_time,
    encode_length,
    encode_oid,
    encode_tag,
)

__all__ = [
    "bit_string",
    "context",
    "generalized_time",
    "integer",
    "null",
    "octet_string",
    "oid",
    "sequence",
    "tlv",
    "utf8_string",
]


def tlv(tag: Tag, content: bytes) -> bytes:
    return encode_tag(tag) + encode_length(len(content)) + content


def sequence(*items: bytes) -> bytes:
    return tlv(Tag(16, True), b"".join(items))


def context(number: int, content: bytes, *, constructed: bool = True) -> bytes:
    """``[number]`` around ``content``: EXPLICIT wrapping, or IMPLICIT when not constructed."""
    return tlv(Tag(number, constructed, TagClass.context), content)


def integer(value: int) -> bytes:
    length = max(1, (value.bit_length() + 8) // 8)
    return tlv(Tag(2), value.to_bytes(length, "big", signed=True))


def octet_string(value: bytes) -> bytes:
    return tlv(Tag(4), value)


def bit_string(value: bytes) -> bytes:
    return tlv(Tag(3), b"\x00" + value)


def null() -> bytes:
    return b"\x05\x00"


def oid(dotted: str) -> bytes:
    return tlv(Tag(6), encode_oid(tuple(int(arc) for arc in dotted.split("."))))


def utf8_string(value: str) -> bytes:
    return tlv(Tag(12), value.encode("utf-8"))


def generalized_time(value: datetime.datetime) -> bytes:
    return tlv(Tag(24), encode_generalized_time(value))
