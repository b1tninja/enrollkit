"""The ir/ip and cr/cp exchange as pure state, RFC 9810 sec. 5.3.1 to 5.3.4 and 5.3.18.

Provenance: messages are built here from the ASN.1 of RFC 9810 Appendix F with the test TLV
helper of ``test_pkiheader.py``; the CertRepMessage body is the minimal legal shape
(``response`` only, ``CertResponse`` with certReqId and a PKIStatusInfo holding the status).
No vendor capture; the roadmap row for captured traffic stays open.
"""

from __future__ import annotations

import pytest
from test_pkiheader import ALG, NAME, NONCE, NULL_DN, TXID, integer, tlv

from enrollkit.flow import ExchangeError, ExchangeState, IrCrExchange
from enrollkit.messages import (
    CMP_2000,
    MessageError,
    build_header,
    build_message,
    general_info_implicit_confirm,
    parse,
    parse_header,
)

SERVER_NONCE = bytes(range(64, 80))


def request_header(**over):
    args = {
        "pvno": CMP_2000,
        "sender": NULL_DN,
        "recipient": NAME,
        "protection_alg": ALG,
        "transaction_id": TXID,
        "sender_nonce": NONCE,
    } | over
    return parse_header(build_header(**args))


def cert_rep(*statuses):
    responses = b"".join(
        tlv(0x30, integer(i) + tlv(0x30, integer(s))) for i, s in enumerate(statuses)
    )
    return tlv(0x30, tlv(0x30, responses))


def reply(body, content, *, txid=TXID, recip_nonce=NONCE, info=()):
    header = build_header(
        pvno=CMP_2000,
        sender=NAME,
        recipient=NULL_DN,
        protection_alg=ALG,
        transaction_id=txid,
        sender_nonce=SERVER_NONCE,
        recip_nonce=recip_nonce,
        general_info=info,
    )
    return parse(build_message(header, body, content, protection=b"x" * 8))


def test_ir_ip_exchange():
    ex = IrCrExchange("ir", request_header())
    with pytest.raises(ExchangeError):
        ex.receive(reply("ip", cert_rep(0)))  # nothing sent yet
    ex.request_sent()
    assert ex.receive(reply("ip", cert_rep(0))) is ExchangeState.NEEDS_CONFIRM
    ex.confirm_sent(sender_nonce=b"\x07" * 16)
    assert ex.receive(reply("pkiconf", b"\x05\x00", recip_nonce=b"\x07" * 16)) is ExchangeState.DONE


def test_exchange_refuses_wrong_echo_and_wrong_body():
    for bad in (
        reply("ip", cert_rep(0), txid=NONCE),  # transactionID not echoed
        reply("ip", cert_rep(0), recip_nonce=SERVER_NONCE),  # recipNonce is not our senderNonce
        reply("cp", cert_rep(0)),  # cp answers a cr, not an ir
    ):
        ex = IrCrExchange("ir", request_header())
        ex.request_sent()
        with pytest.raises(ExchangeError):
            ex.receive(bad)
    ex = IrCrExchange("cr", request_header())
    ex.request_sent()
    assert ex.receive(reply("cp", cert_rep(1))) is ExchangeState.NEEDS_CONFIRM  # grantedWithMods


def test_exchange_waiting_rejection_and_error():
    ex = IrCrExchange("ir", request_header())
    ex.request_sent()
    assert ex.receive(reply("ip", cert_rep(3))) is ExchangeState.WAITING
    ex.poll_sent(sender_nonce=b"\x09" * 16)
    assert ex.receive(reply("ip", cert_rep(2), recip_nonce=b"\x09" * 16)) is ExchangeState.REJECTED
    ex = IrCrExchange("ir", request_header())
    ex.request_sent()
    assert ex.receive(reply("error", tlv(0x30, tlv(0x30, integer(2))))) is ExchangeState.FAILED


def test_implicit_confirm_skips_certconf_only_when_granted():
    ic = general_info_implicit_confirm()
    ex = IrCrExchange("ir", request_header(general_info=[ic]), implicit_confirm=True)
    ex.request_sent()
    assert ex.receive(reply("ip", cert_rep(0), info=[ic])) is ExchangeState.DONE
    ex = IrCrExchange("ir", request_header(general_info=[ic]), implicit_confirm=True)
    ex.request_sent()
    assert ex.receive(reply("ip", cert_rep(0))) is ExchangeState.NEEDS_CONFIRM  # not granted
    ex = IrCrExchange("ir", request_header())
    ex.request_sent()
    assert (
        ex.receive(reply("ip", cert_rep(0), info=[ic])) is ExchangeState.NEEDS_CONFIRM
    )  # not asked


def test_parse_splits_message_into_header_body_protection_and_extra_certs():
    header = build_header(
        pvno=CMP_2000, sender=NAME, recipient=NULL_DN, transaction_id=TXID, protection_alg=ALG
    )
    cert = tlv(0x30, b"\x02\x01\x01")
    raw = build_message(header, "pkiconf", b"\x05\x00", protection=b"abc", extra_certs=[cert])
    message = parse(raw)
    assert message.body_name == "pkiconf"
    assert message.body_tag == 19
    assert message.protection == b"abc"
    assert message.extra_certs == (cert,)
    assert message.header_raw == header
    # ProtectedPart is the received header and body TLVs, which is what protection covers
    assert message.protected_part == tlv(0x30, header + b"\xb3\x02\x05\x00")
    with pytest.raises(MessageError):
        parse(raw + b"\x00")
    with pytest.raises(MessageError):
        parse(tlv(0x30, header + tlv(0x80 | 0x20 | 31, b"")))  # a body tag past [26]
    with pytest.raises(MessageError):
        parse(tlv(0x30, header))  # no body
