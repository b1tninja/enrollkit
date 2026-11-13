"""the HTTPS profile: simpleEnroll, cacerts and curl (RFC 7030).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

import base64
import binascii
from typing import TYPE_CHECKING

from asn1core import Asn1Error, Certificate, parse_certificate
from signeddata import cms

if TYPE_CHECKING:
    from typing import Any

    Auth = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "CmsResponseError",
    "ca_certs",
    "cacerts_response",
    "cms_response",
    "simple_enroll",
]


async def simple_enroll(endpoint: str, csr: bytes, auth: Auth) -> Certificate:
    """Pending behaviour defined by RFC 7030 sec. 4.2.1.

    Not implemented yet. See the ``est.simple_enroll()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("simple_enroll() is not implemented: RFC 7030 sec. 4.2.1")


async def ca_certs(endpoint: str, auth: Auth) -> list:
    """Pending behaviour defined by RFC 7030 sec. 4.1.

    Not implemented yet. See the ``est.ca_certs()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("ca_certs() is not implemented: RFC 7030 sec. 4.1")


class CmsResponseError(Exception):
    """An EST response body is not a certs-only CMS SignedData in base64."""


_MAX_BODY_BYTES = 4 * 1024 * 1024  # policy bound on a /cacerts body, not a protocol limit
_ALLOWED_WHITESPACE = bytes((32, 9, 13, 10))  # space, tab, CR, LF: RFC 8951 sec. 3.1


def cms_response(body: bytes) -> tuple[bytes, ...]:
    """Read an EST certs-only response body and return the DER certificates it carries.

    RFC 8951 sec. 3 makes the body base64 (RFC 4648 sec. 4) of the DER ContentInfo regardless of
    any Content-Transfer-Encoding header, whose value MUST be ignored, so this takes the body
    only and has no header parameter to honour. White space (CR, LF, space, tab) SHOULD be
    tolerated (sec. 3.1) and is stripped; any other non-alphabet octet is refused. The result must
    be the certificates-only SignedData of RFC 7030 sec. 4.1.3 (a CMC Simple PKI Response, RFC
    5272, now obsoleted by RFC 10002): no signers, id-data, no content. Nothing is validated; RFC
    7030 sec. 4.1.3 requires out-of-band validation of the root before the chain is trusted.

    Raises:
        CmsResponseError: not base64, not SignedData, not certs-only, or carrying no certificate.
    """
    if len(body) > _MAX_BODY_BYTES:
        raise CmsResponseError("response body exceeds the size bound")
    squeezed = bytes(b for b in body if b not in _ALLOWED_WHITESPACE)
    try:
        der = base64.b64decode(squeezed, validate=True)
    except binascii.Error as error:
        raise CmsResponseError(f"body is not base64: {error}") from error
    try:
        certificates = cms.certificates_only(der)
    except cms.CmsError as error:
        raise CmsResponseError(f"body is not a certs-only SignedData: {error}") from error
    if not certificates:
        raise CmsResponseError("the response carries no certificate")
    return certificates


def cacerts_response(body: bytes) -> tuple[Certificate, ...]:
    """Parse an EST ``/cacerts`` body into ``asn1core`` certificates (RFC 7030 sec. 4.1.3).

    ``cms_response`` unwraps the certs-only SignedData and this parses each certificate strictly
    with asn1core. The result is a list of what the server sent, root and subordinates alike and
    the optional Root CA Key Update certificates (OldWithOld, OldWithNew, NewWithOld); which one
    is the TA is not decided here, and RFC 7030 sec. 4.1.3 para 5 requires out-of-band validation
    of it before any of them is trusted (row ``est.cacerts-validation``).

    Raises:
        CmsResponseError: the body is not a certs-only response, or a certificate does not parse.
    """
    parsed = []
    for der in cms_response(body):
        try:
            parsed.append(parse_certificate(der))
        except Asn1Error as error:
            raise CmsResponseError(
                f"a certificate in the response does not parse: {error}"
            ) from error
    return tuple(parsed)
