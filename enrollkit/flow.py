"""the transaction state machine including poll and confirm.

Every object in this module is a placeholder until the milestone named in ROADMAP.md lands. A
stub raises instead of returning a plausible empty value: a protocol library that silently
answers nothing is worse than one that refuses to answer.
"""

from __future__ import annotations

import enum
from typing import TYPE_CHECKING

from .bodies import (
    PKI_STATUS_ACCEPTED,
    PKI_STATUS_GRANTED_WITH_MODS,
    PKI_STATUS_REJECTION,
    PKI_STATUS_WAITING,
    POLL_ALL,
    read_error,
    read_poll_rep,
)
from .messages import ID_IT_IMPLICIT_CONFIRM as _IMPLICIT
from .messages import (
    HeaderError,
    MessageError,
    PkiHeader,
    PkiMessage,
    cert_responses,
    check_transaction_echo,
)

if TYPE_CHECKING:
    from typing import Any

    Auth = Any  # placeholder: give it a real type in the milestone that needs it
    Budget = Any  # placeholder: give it a real type in the milestone that needs it
    CrmfRequest = Any  # placeholder: give it a real type in the milestone that needs it
    EnrollmentResult = Any  # placeholder: give it a real type in the milestone that needs it

__all__ = [
    "PKI_STATUS_ACCEPTED",
    "PKI_STATUS_GRANTED_WITH_MODS",
    "PKI_STATUS_REJECTION",
    "PKI_STATUS_WAITING",
    "ExchangeError",
    "ExchangeState",
    "IrCrExchange",
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
    """Pending behaviour defined by RFC 9810 sec. 5.3.22.

    Not implemented yet. See the ``flow.poll_until_ready()`` row in ROADMAP.md; this stub
    raises on purpose so nothing downstream mistakes it for working code.
    """
    raise NotImplementedError("poll_until_ready() is not implemented: RFC 9810 sec. 5.3.22")


# --------------------------------------------------------------------------------------------
# The ir/ip and cr/cp exchange as pure state (RFC 9810 sec. 5.3.1 to 5.3.4, 5.3.18, 5.3.22).

# PKIStatus values, RFC 9810 sec. 5.2.3, are defined in ``bodies`` and re-exported here.


class ExchangeError(Exception):
    """A message arrived that the exchange's current state, or RFC 9810, does not allow."""


class ExchangeState(enum.Enum):
    """Where an ir/cr transaction stands. Nothing here touches a socket or a clock."""

    NEW = "new"  # constructed, request not yet sent
    AWAITING_RESPONSE = "awaiting_response"  # request sent, ip/cp expected
    WAITING = "waiting"  # the server answered status waiting: poll (sec. 5.3.22)
    NEEDS_CONFIRM = "needs_confirm"  # certificate issued, a certConf is owed
    AWAITING_PKICONF = "awaiting_pkiconf"  # certConf sent, pkiconf expected
    DONE = "done"  # certificate issued and the transaction closed
    REJECTED = "rejected"  # the server refused the request
    FAILED = "failed"  # an error message, or a protocol violation, ended it


class IrCrExchange:
    """One initialization (``ir``) or certification (``cr``) transaction as a state machine.

    The caller builds and sends messages and feeds every received ``PkiMessage`` to
    ``receive``; the object checks it against the request (body alternative, transactionID echo,
    recipNonce equal to our senderNonce) and moves. It never decides to retry or sleep, which is
    ``poll_until_ready``'s business, and a message out of turn raises ``ExchangeError`` rather
    than being ignored.

    ``implicit_confirm`` records that the request asked for implicitConfirm (RFC 9810 sec.
    5.1.1.1); the certConf is then skipped only when the response header grants it.
    """

    def __init__(self, kind: str, request_header: PkiHeader, *, implicit_confirm: bool = False):
        if kind not in {"ir", "cr"}:
            raise ValueError("kind must be 'ir' or 'cr'")
        self.kind = kind
        self.state = ExchangeState.NEW
        self.implicit_confirm = implicit_confirm
        self.statuses: tuple[int, ...] = ()
        self._header = request_header
        self._last_sender_nonce = request_header.sender_nonce
        self._granted = False
        self.pending_ids: tuple[int, ...] = ()
        self.check_after: int | None = None
        self._next_poll_at: float | None = None

    @property
    def response_body(self) -> str:
        return "ip" if self.kind == "ir" else "cp"

    def request_sent(self) -> None:
        """Record that the ir/cr went out."""
        self._require(ExchangeState.NEW, "request_sent")
        self.state = ExchangeState.AWAITING_RESPONSE

    def confirm_sent(self, sender_nonce: bytes | None = None) -> None:
        """Record that a certConf went out (owed once the state is NEEDS_CONFIRM)."""
        self._require(ExchangeState.NEEDS_CONFIRM, "confirm_sent")
        self._last_sender_nonce = sender_nonce
        self.state = ExchangeState.AWAITING_PKICONF

    def poll_sent(self, sender_nonce: bytes | None = None, *, now: float | None = None) -> None:
        """Record that a pollReq went out while WAITING, with its senderNonce.

        RFC 9810 sec. 5.3.22 item 3: after a pollRep the end entity waits "at least the number of
        seconds given in the checkAfter field before sending another pollReq". The exchange has no
        clock; pass ``now`` (seconds, on the same scale as the ``now`` given to ``receive``) and a
        poll sent too early raises ``ExchangeError``. Without ``now`` nothing is enforced.
        """
        self._require(ExchangeState.WAITING, "poll_sent")
        if now is not None and self._next_poll_at is not None and now < self._next_poll_at:
            raise ExchangeError(
                f"a pollReq {self._next_poll_at - now:.0f} seconds before checkAfter allows"
            )
        self._last_sender_nonce = sender_nonce
        self._next_poll_at = None
        self.state = ExchangeState.AWAITING_RESPONSE

    def poll_request_ids(self) -> tuple[int, ...]:
        """The certReqIds the next pollReq carries (sec. 5.3.22 item 1).

        The ids of the CertResponses still "waiting", or ``(-1,)`` (``POLL_ALL``) when the
        whole response is pending, as after an ``error`` message with status "waiting" or a
        ``pollRep`` for the complete response.
        """
        self._require(ExchangeState.WAITING, "poll_request_ids")
        return self.pending_ids

    def receive(self, message: PkiMessage, *, now: float | None = None) -> ExchangeState:
        """Feed one received message and return the new state.

        ``now`` is the receive time in seconds; it is used only to enforce ``checkAfter`` on the
        next ``poll_sent``.
        """
        if self.state not in {ExchangeState.AWAITING_RESPONSE, ExchangeState.AWAITING_PKICONF}:
            raise ExchangeError(f"no message is expected in state {self.state.value}")
        header = message.header
        try:
            check_transaction_echo(self._header, header)
        except HeaderError as error:
            raise ExchangeError(str(error)) from error
        if self._header.transaction_id is not None and header.transaction_id is None:
            raise ExchangeError("response omits the transactionID")
        if header.recip_nonce is not None and header.recip_nonce != self._last_sender_nonce:
            raise ExchangeError("recipNonce does not echo our senderNonce")
        name = message.body_name
        if name == "error":
            try:
                waiting = read_error(message).status_info.status == PKI_STATUS_WAITING
            except MessageError:
                waiting = False  # an unreadable error still ends the transaction
            if waiting and self.state is ExchangeState.AWAITING_RESPONSE:
                # RFC 9810 sec. 5.3.21 para 4: poll; ErrorMsgContent has no certReqId, so the
                # pollReq names the whole response with -1 (sec. 5.3.22 item 1).
                self.pending_ids = (POLL_ALL,)
                self.state = ExchangeState.WAITING
            else:
                self.state = ExchangeState.FAILED
            return self.state
        if self.state is ExchangeState.AWAITING_PKICONF:
            if name != "pkiconf":
                raise ExchangeError(f"expected pkiconf, got {name}")
            self.state = ExchangeState.DONE
            return self.state
        if name == "pollRep":
            if self.state is not ExchangeState.AWAITING_RESPONSE:
                raise ExchangeError("a pollRep is only an answer to a pollReq")
            try:
                entries = read_poll_rep(message)
            except MessageError as error:
                raise ExchangeError(str(error)) from error
            if not entries:
                raise ExchangeError("a pollRep with no entry")
            self.check_after = max(entry.check_after for entry in entries)
            self._next_poll_at = None if now is None else now + self.check_after
            self.state = ExchangeState.WAITING
            return self.state
        if name != self.response_body:
            raise ExchangeError(f"expected {self.response_body}, got {name}")
        try:
            responses = cert_responses(message)
        except MessageError as error:
            raise ExchangeError(str(error)) from error
        if not responses:
            raise ExchangeError("a CertRepMessage with no CertResponse")
        self.statuses = tuple(r.status for r in responses)
        self._granted = _IMPLICIT in _info_oids(header)
        if all(s == PKI_STATUS_WAITING for s in self.statuses):
            self.pending_ids = tuple(r.cert_req_id for r in responses)
            self.state = ExchangeState.WAITING
        elif all(s in {PKI_STATUS_ACCEPTED, PKI_STATUS_GRANTED_WITH_MODS} for s in self.statuses):
            skip = self.implicit_confirm and self._granted
            self.state = ExchangeState.DONE if skip else ExchangeState.NEEDS_CONFIRM
        elif PKI_STATUS_REJECTION in self.statuses:
            self.state = ExchangeState.REJECTED
        else:
            raise ExchangeError(f"unhandled PKIStatus values {self.statuses}")
        return self.state

    def _require(self, state: ExchangeState, action: str) -> None:
        if self.state is not state:
            raise ExchangeError(f"{action} is not allowed in state {self.state.value}")


def _info_oids(header: PkiHeader) -> set[str]:
    from asn1core import decode, decode_oid

    found = set()
    for item in header.general_info:
        node, _ = decode(item)
        found.add(".".join(str(a) for a in decode_oid(node.children[0].payload or b"")))
    return found
