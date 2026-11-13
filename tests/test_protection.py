"""PasswordBasedMac (RFC 4211 sec. 4.4, RFC 9045, RFC 9810 sec. 5.1.3.1).

Provenance: none of the RFCs prints a PBM test vector. ``reference_key`` below restates the RFC
4211 pseudo-code (salt appended, hash iterated) and the RFC 9810 expansion directly on hashlib,
with no shared code, and the expected tag is computed with hmac over that key. It is an
independent reading of the text, not a vendor vector; the roadmap row for an OpenSSL capture
stays open.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from enrollkit.protection import (
    PbmError,
    PbmParameter,
    pbm_algorithm_identifier,
    pbm_key,
    pbm_mac,
    pbm_verify,
    protected_part,
    read_pbm_algorithm,
)

SHA1 = "1.3.14.3.2.26"
SHA256 = "2.16.840.1.101.3.4.2.1"
HMAC_SHA1 = "1.3.6.1.5.5.8.1.2"
HMAC_SHA256 = "1.2.840.113549.2.9"


def reference_key(pw: bytes, salt: bytes, owf: str, count: int, klen: int) -> bytes:
    k = pw + salt
    for _ in range(count):
        k = hashlib.new(owf, k).digest()
    if klen <= len(k):
        return k[:klen]
    out = k
    n = 1
    while len(out) < klen:
        out += hashlib.new(owf, bytes([0x30 + n]) + k).digest()
        n += 1
    return out[:klen]


def test_pbm_known_answer():
    salt = bytes.fromhex("0102030405060708")
    data = b"protected part"
    same = PbmParameter(salt, SHA256, 500, HMAC_SHA256)
    key = reference_key(b"secret", salt, "sha256", 500, 32)
    assert pbm_key(b"secret", same) == key
    assert pbm_mac(b"secret", same, data) == hmac.new(key, data, "sha256").digest()
    # K > H: SHA-1 OWF (20 octets) feeding HMAC-SHA256 (32) takes the RFC 9810 expansion.
    expand = PbmParameter(salt, SHA1, 100, HMAC_SHA256)
    key = reference_key(b"secret", salt, "sha1", 100, 32)
    assert pbm_key(b"secret", expand) == key
    assert key[20:] == hashlib.sha1(b"1" + key[:20]).digest()[:12]  # noqa: S324
    # K <= H: the most significant K bits are used.
    short = PbmParameter(salt, SHA256, 100, HMAC_SHA1)
    assert pbm_key(b"secret", short) == reference_key(b"secret", salt, "sha256", 100, 20)
    tag = pbm_mac(b"secret", same, data)
    assert pbm_verify(b"secret", same, data, tag)
    assert not pbm_verify(b"secret2", same, data, tag)
    assert not pbm_verify(b"secret", same, data + b"x", tag)


def test_pbm_algorithm_identifier_round_trips_and_policy():
    parameter = PbmParameter(b"saltsalt", SHA256, 10000, HMAC_SHA256)
    assert read_pbm_algorithm(pbm_algorithm_identifier(parameter)) == parameter
    with pytest.raises(PbmError):
        PbmParameter(b"saltsalt", SHA256, 99, HMAC_SHA256)  # RFC 4211: MUST be at least 100
    with pytest.raises(PbmError):
        PbmParameter(b"saltsalt", "1.2.3", 100, HMAC_SHA256)
    with pytest.raises(PbmError):
        read_pbm_algorithm(b"\x30\x05\x06\x03\x2a\x03\x04")
    assert PbmParameter(b"1234567", SHA256, 100, HMAC_SHA256).short_salt()


def test_protected_part_is_sequence_of_header_and_body():
    assert protected_part(b"\x30\x00", b"\xa0\x00") == bytes.fromhex("30043000a000")
