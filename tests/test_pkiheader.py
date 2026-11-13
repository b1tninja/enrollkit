"""PKIHeader parsing, RFC 9810 sec. 5.1.1.

Provenance of every fixture: RFC 9810 prints no encoded PKIHeader, so each one is built here from
the ASN.1 of Appendix F (an ``EXPLICIT TAGS`` module) with a four-line TLV helper that shares no
code with asn1core. It is not a vendor capture; the roadmap row for captured traffic stays open.
"""

from __future__ import annotations

import datetime

import pytest

from enrollkit.messages import (
    CMP_2000,
    CMP_2021,
    HeaderError,
    PkiHeader,
    check_transaction_echo,
    is_null_dn,
    parse_header,
)


def tlv(tag: int, content: bytes) -> bytes:
    if len(content) < 0x80:
        length = bytes([len(content)])
    else:
        body = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(body)]) + body
    return bytes([tag]) + length + content


def integer(value: int) -> bytes:
    return tlv(0x02, bytes([value]))


def octets(value: bytes) -> bytes:
    return tlv(0x04, value)


NULL_DN = tlv(0xA4, tlv(0x30, b""))
NAME = tlv(0xA4, tlv(0x30, tlv(0x31, tlv(0x30, bytes.fromhex("0603550403") + tlv(0x0C, b"ca")))))
ALG = tlv(0x30, bytes.fromhex("06092a864886f70d01010b") + bytes.fromhex("0500"))
NONCE = bytes(range(16))
TXID = bytes(range(0x80, 0x90))


def header(*optional: bytes, pvno: int = CMP_2000, sender: bytes = NULL_DN) -> bytes:
    return tlv(0x30, integer(pvno) + sender + NAME + b"".join(optional))


def field(number: int, inner: bytes) -> bytes:
    return tlv(0xA0 | number, inner)


def test_transaction_id_is_echoed_and_nonce_lengths_are_reported():
    request = parse_header(
        header(field(4, octets(TXID)), field(5, octets(NONCE)), field(6, octets(b"\x01" * 8)))
    )
    response = parse_header(header(field(4, octets(TXID)), field(5, octets(NONCE))))
    assert request.transaction_id == TXID
    assert len(request.sender_nonce or b"") == 16
    assert request.short_nonces() == ("recip_nonce",)
    assert response.short_nonces() == ()
    check_transaction_echo(request, response)
    wrong = parse_header(header(field(4, octets(b"\x00" * 16))))
    with pytest.raises(HeaderError):
        check_transaction_echo(request, wrong)
    with pytest.raises(HeaderError):
        check_transaction_echo(request, parse_header(header()))
    # a request with no transactionID imposes nothing on the response
    check_transaction_echo(parse_header(header()), wrong)


def test_every_field_parses_and_stored_tlvs_are_the_bytes_received():
    when = b"20261113120000Z"
    der = header(
        field(0, tlv(0x18, when)),
        field(1, ALG),
        field(2, octets(b"kid-s")),
        field(3, octets(b"kid-r")),
        field(4, octets(TXID)),
        field(5, octets(NONCE)),
        field(6, octets(NONCE)),
        field(7, tlv(0x30, tlv(0x0C, b"hello") + tlv(0x0C, "café".encode()))),
        field(8, tlv(0x30, tlv(0x30, bytes.fromhex("06082b0601050507040d0500")))),
    )
    parsed = parse_header(der)
    assert parsed.pvno == CMP_2000
    assert parsed.version_name == "cmp2000"
    assert parsed.sender == NULL_DN
    assert parsed.recipient == NAME
    assert parsed.message_time == datetime.datetime(2026, 11, 13, 12, 0, 0, tzinfo=datetime.UTC)
    assert parsed.protection_alg == ALG
    assert (parsed.sender_kid, parsed.recip_kid) == (b"kid-s", b"kid-r")
    assert parsed.free_text == ("hello", "café")
    assert len(parsed.general_info) == 1
    assert parsed.general_info[0].startswith(b"\x30")


def test_null_dn_sender_is_recognised():
    assert is_null_dn(parse_header(header()).sender)
    named = parse_header(header(sender=NAME))
    assert not is_null_dn(named.sender)
    assert not is_null_dn(tlv(0xA4, tlv(0x30, tlv(0x31, b""))))


def test_pvno_unknown_is_reported_not_guessed():
    unknown = parse_header(header(pvno=9))
    assert unknown.pvno == 9
    assert unknown.version_name is None
    assert parse_header(header(pvno=CMP_2021)).version_name == "cmp2021"


def test_header_with_trailing_bytes_refused():
    with pytest.raises(HeaderError):
        parse_header(header() + b"\x00")


def test_optional_fields_absent_are_none_not_empty_bytes():
    parsed = parse_header(header())
    assert parsed == PkiHeader(pvno=CMP_2000, sender=NULL_DN, recipient=NAME)
    assert parsed.transaction_id is None
    assert parsed.sender_nonce is None
    assert parsed.free_text == ()
    present_empty = parse_header(header(field(4, octets(b""))))
    assert present_empty.transaction_id == b""


def test_tag_order_violation_refused():
    with pytest.raises(HeaderError):
        parse_header(header(field(5, octets(NONCE)), field(4, octets(TXID))))
    with pytest.raises(HeaderError):
        parse_header(header(field(4, octets(TXID)), field(4, octets(TXID))))


def test_oversized_free_text_bounded():
    too_many = tlv(0x30, tlv(0x0C, b"x") * 33)
    with pytest.raises(HeaderError):
        parse_header(header(field(7, too_many)))
    too_long = tlv(0x30, tlv(0x0C, b"y" * 5000))
    with pytest.raises(HeaderError):
        parse_header(header(field(7, too_long)))
    with pytest.raises(HeaderError):
        parse_header(header(field(7, tlv(0x30, b""))))
    with pytest.raises(HeaderError):
        parse_header(header(field(7, tlv(0x30, tlv(0x0C, b"\xff\xfe")))))


def test_implicit_tagging_is_refused_because_the_module_is_explicit():
    # transactionID [4] written IMPLICIT (a4 not wrapping an OCTET STRING) is a different encoding.
    with pytest.raises(HeaderError):
        parse_header(header(tlv(0x84, TXID)))


def test_unknown_field_number_and_non_der_refused():
    with pytest.raises(HeaderError):
        parse_header(header(field(9, octets(b"x"))))
    with pytest.raises(HeaderError):
        parse_header(tlv(0x30, tlv(0x02, b"\x00\x02") + NULL_DN + NAME))  # non-minimal INTEGER
    with pytest.raises(HeaderError):
        parse_header(b"")
    with pytest.raises(HeaderError):
        parse_header(tlv(0x30, integer(2) + NULL_DN))  # no recipient


def test_sender_must_be_a_general_name():
    with pytest.raises(HeaderError):
        parse_header(header(sender=tlv(0x04, b"x")))
    with pytest.raises(HeaderError):
        parse_header(header(sender=tlv(0xAF, b"")))
