"""request objects, keys and proof of possession (RFC 4211).

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

    CrmfRequest = Any  # placeholder: give it a real type in the milestone that needs it
    Validity = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "build_request",
]


def build_request(public_key: object, subject: str, validity: Validity) -> CrmfRequest:
    """Pending behaviour defined by RFC 4211.

    Not implemented yet. See the ``crmf.build_request()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("build_request() is not implemented: RFC 4211")
