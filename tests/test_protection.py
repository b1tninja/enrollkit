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
import json
import pathlib

import pytest

from enrollkit.messages import parse
from enrollkit.protection import (
    ID_AES128_GMAC,
    ID_AES256_GMAC,
    ID_PBMAC1,
    KEY_BASEKEY,
    GmacParameter,
    Pbmac1Parameter,
    PbmError,
    PbmParameter,
    gmac_algorithm_identifier,
    gmac_mac,
    gmac_verify,
    pbm_algorithm_identifier,
    pbm_key,
    pbm_mac,
    pbm_verify,
    pbmac1_algorithm_identifier,
    pbmac1_key,
    pbmac1_mac,
    pbmac1_verify,
    protected_part,
    read_gmac_algorithm,
    read_pbm_algorithm,
    read_pbmac1_algorithm,
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


# --- OpenSSL captures and a second implementation -------------------------------------------------
#
# Provenance: ``tests/vectors/openssl-3.5.6-cmp-ir-pbm.json`` holds four ``ir`` requests written by
# ``openssl cmp -reqout_only`` (OpenSSL 3.5.6), each protected with id-PasswordBasedMac under the
# password in that file. The PBMAC1 and GMAC values below were computed by the same OpenSSL with
# ``openssl kdf PBKDF2``, ``openssl mac HMAC`` and ``openssl mac -cipher AES-*-GCM GMAC``, from the
# inputs written next to each. None of it comes from this package.

OPENSSL_VECTORS = json.loads(
    (pathlib.Path(__file__).parent / "vectors" / "openssl-3.5.6-cmp-ir-pbm.json").read_text()
)


def openssl_request(name):
    message = parse(bytes.fromhex(OPENSSL_VECTORS["requests"][name]))
    assert message.protection is not None
    assert message.header.protection_alg is not None
    parameter = read_pbm_algorithm(message.header.protection_alg)
    return message, parameter, OPENSSL_VECTORS["password"].encode()


def test_pbm_matches_openssl_capture():
    """A PBM-protected request written by OpenSSL verifies, when the key rule is OpenSSL's."""
    for name in OPENSSL_VECTORS["requests"]:
        message, parameter, password = openssl_request(name)
        assert pbm_verify(
            password, parameter, message.protected_part, message.protection, rule=KEY_BASEKEY
        ), name
    # a wrong password, and a changed byte of the protected part, do not verify
    message, parameter, password = openssl_request("sha256_owf_hmacWithSHA256")
    assert not pbm_verify(b"wrong", parameter, message.protected_part, message.protection)
    assert not pbm_verify(password, parameter, message.protected_part + b"\x00", message.protection)


def test_rfc9810_key_rule_agrees_with_openssl_only_when_the_sizes_match():
    """RFC 9810 sec. 5.1.3.1 against OpenSSL 3.5.6: they differ whenever K and H differ.

    With SHA-256 as OWF and HMAC-SHA256 (K = H = 32) both give the same key. With a SHA-1 OWF and
    HMAC-SHA256 the RFC text expands 20 octets to 32; with HMAC-SHA1 under a SHA-256 OWF it takes
    the first 20 of 32. OpenSSL does neither and keys the HMAC with all of BASEKEY. The RFC does not
    say what K is for HMAC, so this library keeps the RFC reading by default and offers OpenSSL's as
    ``KEY_BASEKEY`` (ROADMAP.md, ``protection.pbm-hmac-key-length``).
    """
    agree = {"sha256_owf_hmacWithSHA256": True}
    differ = ("sha256_owf_hmacSHA1_ipsec_oid", "sha256_owf_hmacWithSHA1", "sha1_owf_hmacWithSHA256")
    for name in OPENSSL_VECTORS["requests"]:
        message, parameter, password = openssl_request(name)
        verifies = pbm_verify(password, parameter, message.protected_part, message.protection)
        assert verifies is agree.get(name, False), name
        assert name in agree or name in differ


# PBMAC1: PBKDF2 then HMAC, over b"protected part data" with the password b"secret-pass" and the
# salt 000102...0f. Each tuple: PBKDF2 PRF OID, iterations, keyLength, HMAC OID, derived key,
# MAC. Computed with ``openssl kdf PBKDF2`` and ``openssl mac HMAC``.
PBMAC1_DATA = b"protected part data"
PBMAC1_VECTORS = [
    (
        "1.2.840.113549.2.9",
        1000,
        32,
        "1.2.840.113549.2.9",
        "ea8c902c50ca9b459802e18ede9fe08fcd27fbb348b0099853c1d35bc81023a1",
        "4787e3b5ec49e98aafa910db5f33b2236208ec7b8f96be63ff39984b34095bbc",
    ),
    (
        "1.2.840.113549.2.7",
        1000,
        20,
        "1.2.840.113549.2.7",
        "9269290ca26e6cd912ac52615e02a22da62f6e89",
        "d982302f3156486e4d6ba3735b9145dc11dcc8ca",
    ),
    (
        "1.2.840.113549.2.11",
        2000,
        48,
        "1.2.840.113549.2.10",
        "0181c90e0dba9025962f81a441bc518540ef6ff617a7cae00a907818bbdff4211920de0e8343f7a146194905ce239428",
        "2c2a8cf2706b3522cdd6458adbd13ffda3df24c54e92c2e7a03a1270ea994ffd96c2f36d68dbef74c4008e95056fb523",
    ),
]


@pytest.mark.parametrize(("prf", "count", "length", "mac", "dk", "tag"), PBMAC1_VECTORS)
def test_pbmac1_and_aes_gmac(prf, count, length, mac, dk, tag):
    """PBMAC1 (RFC 8018 sec. 7.1) matches OpenSSL's PBKDF2 and HMAC, through its own algorithm id."""
    parameter = Pbmac1Parameter(bytes(range(16)), count, length, prf, mac)
    assert pbmac1_key(b"secret-pass", parameter).hex() == dk
    assert pbmac1_mac(b"secret-pass", parameter, PBMAC1_DATA).hex() == tag
    assert pbmac1_verify(b"secret-pass", parameter, PBMAC1_DATA, bytes.fromhex(tag))
    assert not pbmac1_verify(b"secret-pasx", parameter, PBMAC1_DATA, bytes.fromhex(tag))
    assert read_pbmac1_algorithm(pbmac1_algorithm_identifier(parameter)) == parameter


def test_pbmac1_algorithm_identifier_bytes_and_default_prf():
    """DER omits the PRF when it is the DEFAULT id-hmacWithSHA1 (RFC 8018 appendix A.2)."""
    sha1 = Pbmac1Parameter(bytes(range(4)), 1000, 20, "1.2.840.113549.2.7", "1.2.840.113549.2.7")
    # SEQUENCE { id-PBMAC1, SEQUENCE { SEQUENCE { id-PBKDF2, SEQUENCE { salt, 1000, 20 } },
    #                                  SEQUENCE { id-hmacWithSHA1, NULL } } }
    assert pbmac1_algorithm_identifier(sha1).hex() == (
        "3037"
        "06092a864886f70d01050e"
        "302a"
        "301a"
        "06092a864886f70d01050c"
        "300d"
        "040400010203"
        "020203e8"
        "020114"
        "300c"
        "06082a864886f70d02070500"
    )
    sha256 = Pbmac1Parameter(bytes(range(4)), 1000, 32, "1.2.840.113549.2.9", "1.2.840.113549.2.9")
    encoded = pbmac1_algorithm_identifier(sha256)
    assert bytes.fromhex("06082a864886f70d02090500") in encoded  # the PRF is written
    assert read_pbmac1_algorithm(encoded) == sha256
    assert encoded.count(bytes.fromhex("06082a864886f70d0209")) == 2  # PRF and message auth scheme


def test_pbmac1_refusals():
    good = Pbmac1Parameter(bytes(range(4)), 1000, 32, "1.2.840.113549.2.9", "1.2.840.113549.2.9")
    with pytest.raises(
        PbmError, match="keyLength"
    ):  # keyLength is OPTIONAL in RFC 8018, required here
        read_pbmac1_algorithm(_without_key_length(good))
    with pytest.raises(PbmError):
        Pbmac1Parameter(b"", 1000, 32, "1.2.840.113549.2.9", "1.2.840.113549.2.9")  # no salt
    with pytest.raises(PbmError):
        Pbmac1Parameter(b"s", 0, 32, "1.2.840.113549.2.9", "1.2.840.113549.2.9")
    with pytest.raises(PbmError):
        Pbmac1Parameter(b"s", 1, 32, "2.16.840.1.101.3.4.1.9", "1.2.840.113549.2.9")  # GMAC as PRF
    with pytest.raises(PbmError, match="not id-PBMAC1"):
        read_pbmac1_algorithm(
            pbm_algorithm_identifier(PbmParameter(b"saltsalt", SHA256, 100, HMAC_SHA256))
        )
    with pytest.raises(PbmError):
        read_pbmac1_algorithm(b"\x30\x00")


def _without_key_length(parameter):
    """A PBMAC1 identifier with PBKDF2 keyLength left out, written here by hand."""
    from enrollkit import _der

    kdf_params = _der.sequence(
        _der.octet_string(parameter.salt),
        _der.integer(parameter.iterations),
        _der.sequence(_der.oid(parameter.prf), _der.null()),
    )
    kdf = _der.sequence(_der.oid("1.2.840.113549.1.5.12"), kdf_params)
    scheme = _der.sequence(_der.oid(parameter.mac), _der.null())
    return _der.sequence(_der.oid(ID_PBMAC1), _der.sequence(kdf, scheme))


GMAC_NONCE = bytes.fromhex("a0a1a2a3a4a5a6a7a8a9aaab")
GMAC_VECTORS = [
    (ID_AES128_GMAC, "000102030405060708090a0b0c0d0e0f", "f61c8f211a9701423d0619b679f4c02b"),
    (
        ID_AES256_GMAC,
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "195993d0dfc66b51388c03049d8853f1",
    ),
]


@pytest.mark.parametrize(("algorithm", "key", "tag"), GMAC_VECTORS)
def test_aes_gmac_matches_openssl(algorithm, key, tag):
    """AES-GMAC (RFC 9044) with a shared key, against ``openssl mac -cipher AES-*-GCM GMAC``."""
    parameter = GmacParameter(algorithm, GMAC_NONCE)
    assert gmac_mac(bytes.fromhex(key), parameter, PBMAC1_DATA).hex() == tag
    assert gmac_verify(bytes.fromhex(key), parameter, PBMAC1_DATA, bytes.fromhex(tag))
    assert not gmac_verify(bytes.fromhex(key), parameter, PBMAC1_DATA + b"!", bytes.fromhex(tag))
    assert read_gmac_algorithm(gmac_algorithm_identifier(parameter)) == parameter
    # a shorter tag is the leading octets (RFC 9044 MACLength 12 to 16)
    short = GmacParameter(algorithm, GMAC_NONCE, 12)
    assert gmac_mac(bytes.fromhex(key), short, PBMAC1_DATA).hex() == tag[:24]


def test_aes_gmac_parameters_follow_der_defaults_and_refuse_bad_input():
    parameter = GmacParameter(ID_AES128_GMAC, GMAC_NONCE)
    # SEQUENCE { id-aes128-GMAC, SEQUENCE { nonce, 16 } }: the length 16 is not the DEFAULT 12
    assert gmac_algorithm_identifier(parameter).hex() == (
        "301e06096086480165030401093011040ca0a1a2a3a4a5a6a7a8a9aaab020110"
    )
    twelve = gmac_algorithm_identifier(GmacParameter(ID_AES128_GMAC, GMAC_NONCE, 12))
    assert twelve.hex().endswith("040ca0a1a2a3a4a5a6a7a8a9aaab")  # length 12 is omitted by DER
    assert read_gmac_algorithm(twelve).length == 12
    with pytest.raises(PbmError, match="needs a 16"):
        gmac_mac(b"k" * 15, parameter, b"data")
    with pytest.raises(PbmError, match="needs a 32"):
        gmac_mac(b"k" * 16, GmacParameter(ID_AES256_GMAC, GMAC_NONCE), b"data")
    with pytest.raises(PbmError):
        GmacParameter("1.2.3", GMAC_NONCE)
    with pytest.raises(PbmError):
        GmacParameter(ID_AES128_GMAC, GMAC_NONCE, 11)
    with pytest.raises(PbmError, match="nonce"):
        GmacParameter(ID_AES128_GMAC, b"short")
    with pytest.raises(PbmError, match="MUST be present"):
        read_gmac_algorithm(bytes.fromhex("300b0609608648016503040109"))


def test_pbm_with_aes_gmac_as_the_mac():
    """RFC 9045 sec. 4.4: PBM may name AES-GMAC (128 bit key), whose nonce rides in the mac id."""
    parameter = PbmParameter(
        bytes.fromhex("0102030405060708"), SHA256, 500, ID_AES128_GMAC, mac_nonce=GMAC_NONCE
    )
    # the key is the first 16 octets of BASEKEY, 030c...; the tag is OpenSSL's GMAC under it
    assert pbm_key(b"pw", parameter).hex() == "030ce293241f2aa7bc5ec8e64680bb15"
    tag = pbm_mac(b"pw", parameter, PBMAC1_DATA)
    assert tag.hex() == "dacf339066bfc58aa5cc971272a26e7f"
    assert pbm_verify(b"pw", parameter, PBMAC1_DATA, tag)
    assert read_pbm_algorithm(pbm_algorithm_identifier(parameter)) == parameter
    # the key rule has no say for GMAC: it needs exactly its key size
    assert pbm_key(b"pw", parameter, rule=KEY_BASEKEY) == pbm_key(b"pw", parameter)
    with pytest.raises(PbmError):
        PbmParameter(b"saltsalt", SHA256, 500, ID_AES128_GMAC)  # a GMAC mac needs its nonce
    with pytest.raises(PbmError):
        PbmParameter(b"saltsalt", SHA256, 500, HMAC_SHA256, mac_nonce=GMAC_NONCE)
    with pytest.raises(ValueError, match="rule"):
        pbm_key(b"pw", parameter, rule="other")
