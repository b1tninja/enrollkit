"""the transaction state machine including poll and confirm.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    Auth = Any  # placeholder: give it a real type in the milestone that needs it
    Budget = Any  # placeholder: give it a real type in the milestone that needs it
    CrmfRequest = Any  # placeholder: give it a real type in the milestone that needs it
    EnrollmentResult = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "enroll",
    "poll_until_ready",
]


async def enroll(endpoint: str, request: CrmfRequest, auth: Auth) -> EnrollmentResult:
    """Pending behaviour defined by RFC 9810.

    Not implemented yet. See the ``flow.enroll()`` row in ROADMAP.md; this stub raises on
    purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("enroll() is not implemented: RFC 9810")


async def poll_until_ready(endpoint: str, transaction: bytes, budget: Budget) -> EnrollmentResult:
    """Pending behaviour defined by RFC 9810.

    Not implemented yet. See the ``flow.poll_until_ready()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("poll_until_ready() is not implemented: RFC 9810")
