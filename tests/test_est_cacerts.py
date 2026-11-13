"""EST /cacerts bodies: RFC 7030 sec. 4.1.3 as updated by RFC 8951 sec. 3 and 3.1.

Provenance: the certificates are generated per run with ``cryptography``; the certs-only
SignedData around them is written here from RFC 5652 sec. 5.1 with the test TLV helper (version
1, no digest algorithms, id-data, ``certificates [0]``, no signers), not with signeddata. The
base64 layouts (single line, MIME-wrapped, with tabs) are RFC 8951 sec. 3.1's tolerated forms.
"""

from __future__ import annotations

import base64
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from test_pkiheader import integer, tlv

from enrollkit.est import CmsResponseError, cms_response

ID_SIGNED_DATA = bytes.fromhex("06092a864886f70d010702")
ID_DATA = bytes.fromhex("06092a864886f70d010701")


def certificate(name: str) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def signed_data(*certs: bytes, signers: bytes = b"") -> bytes:
    inner = (
        integer(1)
        + tlv(0x31, b"")
        + tlv(0x30, ID_DATA)
        + tlv(0xA0, b"".join(certs))
        + tlv(0x31, signers)
    )
    return tlv(0x30, ID_SIGNED_DATA + tlv(0xA0, tlv(0x30, inner)))


CERTS = (certificate("root"), certificate("sub"))


def test_response_accepts_missing_content_transfer_encoding():
    der = signed_data(*CERTS)
    one_line = base64.b64encode(der)
    assert cms_response(one_line) == CERTS
    # MIME-style wrapping with CRLF, and tabs and spaces: SHOULD be tolerated (sec. 3.1)
    text = base64.encodebytes(der).replace(b"\n", b"\r\n")
    assert cms_response(text) == CERTS
    assert cms_response(b"\t " + one_line[:20] + b" \r\n" + one_line[20:] + b"\n") == CERTS


def test_response_refuses_what_is_not_a_certs_only_response():
    der = signed_data(*CERTS)
    with pytest.raises(CmsResponseError):
        cms_response(der)  # raw DER, not base64
    with pytest.raises(CmsResponseError):
        cms_response(base64.b64encode(der)[:-3] + b"!!!")
    with pytest.raises(CmsResponseError):
        cms_response(base64.b64encode(signed_data(*CERTS, signers=tlv(0x30, integer(1)))))
    with pytest.raises(CmsResponseError):
        cms_response(base64.b64encode(signed_data()))  # no certificate at all
    with pytest.raises(CmsResponseError):
        cms_response(b"")


def test_cacerts_response_parses_each_certificate_with_asn1core():
    from enrollkit.est import cacerts_response

    parsed = cacerts_response(base64.b64encode(signed_data(*CERTS)))
    assert len(parsed) == 2
    assert [c.raw for c in parsed] == list(CERTS)
    broken = signed_data(CERTS[0], tlv(0x30, b"\x02\x01\x01"))
    with pytest.raises(CmsResponseError, match="does not parse"):
        cacerts_response(base64.b64encode(broken))
