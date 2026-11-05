"""POPOSIMESTAMP, POPOWITNESS and signature protection (RFC 9810).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    PkiMessage = Any  # placeholder: give it a real type in the milestone that needs it
    Trust = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "protect",
    "verify_protection",
]


def protect(msg: PkiMessage, secret: bytes) -> PkiMessage:
    """Pending behaviour defined by RFC 9810.

    Not implemented yet. See the ``protection.protect()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("protect() is not implemented: RFC 9810")


def verify_protection(msg: PkiMessage, trust: Trust) -> None:
    """Pending behaviour defined by RFC 9810.

    Not implemented yet. See the ``protection.verify_protection()`` row in ROADMAP.md;
    this stub raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("verify_protection() is not implemented: RFC 9810")
