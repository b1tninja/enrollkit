"""the HTTPS profile: simpleEnroll, cacerts and curl (RFC 7030).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Auth = Any  # placeholder: give it a real type in the milestone that needs it
    Certificate = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "ca_certs",
    "simple_enroll",
]


async def simple_enroll(endpoint: str, csr: bytes, auth: Auth) -> Certificate:
    """Pending behaviour defined by RFC 7030.

    Not implemented yet. See the ``est.simple_enroll()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("simple_enroll() is not implemented: RFC 7030")


async def ca_certs(endpoint: str, auth: Auth) -> list:
    """Pending behaviour defined by RFC 7030.

    Not implemented yet. See the ``est.ca_certs()`` row in ROADMAP.md; this stub raises
    on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("ca_certs() is not implemented: RFC 7030")
