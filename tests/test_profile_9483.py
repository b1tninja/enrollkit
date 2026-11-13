"""RFC 9483 sec. 3.1 header rules, and building a PKIHeader (RFC 9810 sec. 5.1.1).

Provenance: RFC 9483 prints no encoded header. Expected bytes for the round trip are written
out by hand from the ASN.1 of RFC 9810 Appendix F (EXPLICIT TAGS) in ``test_pkiheader.py``'s
independent TLV helper, so the builder is compared with a second encoder, not with itself.
"""

from __future__ import annotations

import datetime

from test_pkiheader import ALG, NAME, NONCE, NULL_DN, TXID, field, integer, octets, tlv

from enrollkit.messages import (
    CMP_2000,
    CMP_2021,
    build_header,
    check_header_9483,
    directory_name_cn,
    general_info_cert_profile,
    general_info_confirm_wait_time,
    general_info_implicit_confirm,
    parse_header,
)

NOW = datetime.datetime(2026, 11, 13, 12, 0, 0, tzinfo=datetime.UTC)
NONCE2 = bytes(range(32, 48))


def good(**over):
    args = {
        "pvno": CMP_2000,
        "sender": NULL_DN,
        "recipient": NAME,
        "protection_alg": ALG,
        "transaction_id": TXID,
        "sender_nonce": NONCE,
    } | over
    return parse_header(build_header(**args))


def test_build_header_round_trips():
    der = build_header(
        pvno=CMP_2021,
        sender=NULL_DN,
        recipient=NAME,
        message_time=NOW,
        protection_alg=ALG,
        sender_kid=b"kid",
        recip_kid=b"rk",
        transaction_id=TXID,
        sender_nonce=NONCE,
        recip_nonce=NONCE2,
        free_text=("hi",),
        general_info=[general_info_implicit_confirm()],
    )
    ts = tlv(0x18, b"20261113120000Z")
    expected = tlv(
        0x30,
        integer(3)
        + NULL_DN
        + NAME
        + field(0, ts)
        + field(1, ALG)
        + field(2, octets(b"kid"))
        + field(3, octets(b"rk"))
        + field(4, octets(TXID))
        + field(5, octets(NONCE))
        + field(6, octets(NONCE2))
        + field(7, tlv(0x30, tlv(0x0C, b"hi")))
        + field(
            8,
            tlv(
                0x30,
                tlv(0x30, bytes.fromhex("06082b06010505070 40d".replace(" ", "")) + b"\x05\x00"),
            ),
        ),
    )
    assert der == expected
    parsed = parse_header(der)
    assert parsed.message_time == NOW
    assert parsed.recip_nonce == NONCE2
    assert parsed.free_text == ("hi",)


def test_header_profile_rules():
    first = good(general_info=[general_info_implicit_confirm()])
    assert check_header_9483(first, "ir", first_message=True) == ()
    # pvno 3 only when EnvelopedData is expected or certConf carries hashAlg.
    assert check_header_9483(first, "ir", first_message=True, enveloped_data=True)
    v3 = good(pvno=CMP_2021)
    assert check_header_9483(v3, "certConf", first_message=True, cert_conf_hash_alg=True) == ()
    assert check_header_9483(v3, "ir", first_message=True)
    # required fields, nonce sizes, first-message recipNonce
    assert check_header_9483(good(protection_alg=None), "ir", first_message=True)
    assert check_header_9483(good(transaction_id=b"\x01" * 8), "ir", first_message=True)
    assert check_header_9483(good(sender_nonce=b"\x01" * 8), "ir", first_message=True)
    assert check_header_9483(good(recip_nonce=NONCE2), "ir", first_message=True)
    # follow-up: transactionID and recipNonce echo the previous message
    reply = good(sender_nonce=NONCE2, recip_nonce=NONCE)
    assert check_header_9483(reply, "ip", first_message=False, previous=first) == ()
    bad = good(sender_nonce=NONCE2, recip_nonce=NONCE2, transaction_id=NONCE)
    assert len(check_header_9483(bad, "ip", first_message=False, previous=first)) == 2


def test_header_profile_mac_sender_and_general_info():
    sender = directory_name_cn("ref-1")
    mac = good(sender=sender, sender_kid=b"ref-1")
    assert check_header_9483(mac, "ir", first_message=True, protection="mac") == ()
    wrong = good(sender=sender, sender_kid=b"other")
    assert check_header_9483(wrong, "ir", first_message=True, protection="mac")
    assert check_header_9483(good(), "ir", first_message=True, protection="mac")
    sig = good(sender_kid=b"ski")
    assert check_header_9483(sig, "ir", first_message=True, protection_cert_ski=b"ski") == ()
    assert check_header_9483(sig, "ir", first_message=True, protection_cert_ski=b"x")
    # implicitConfirm prohibited outside request/response bodies; confirmWaitTime rules
    ic = good(general_info=[general_info_implicit_confirm()])
    assert check_header_9483(ic, "certConf", first_message=True)
    both = good(general_info=[general_info_implicit_confirm(), general_info_confirm_wait_time(NOW)])
    assert any(
        "PROHIBITED with implicitConfirm" in p
        for p in check_header_9483(both, "ip", first_message=True)
    )
    wait = good(general_info=[general_info_confirm_wait_time(NOW)])
    assert any("messageTime" in p for p in check_header_9483(wait, "ip", first_message=True))
    timed = good(message_time=NOW, general_info=[general_info_confirm_wait_time(NOW)])
    assert check_header_9483(timed, "ip", first_message=True) == ()
    # certProfile: ir/cr/kur/p10cr/genm only
    prof = good(general_info=[general_info_cert_profile("tls-server")])
    assert check_header_9483(prof, "ir", first_message=True) == ()
    assert check_header_9483(prof, "genm", first_message=True) == ()
    assert check_header_9483(prof, "ip", first_message=True)
