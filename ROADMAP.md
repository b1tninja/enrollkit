# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation enrollkit could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

A Where cell marked `(to be written)` names the test that will pin the row once it exists; no
such test has been written yet, and the row cannot leave `[ ]` until it has. The Milestone
column places the row on the ladder in section 2, and `-` means it is not placed yet.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `messages.build_cr()` | RFC 9810 sec. 5.3.3 | `[ ]` | `tests/test_obligations.py::test_build_cr` (to be written) | M1 |
| `messages.parse()` | RFC 9810 sec. 5.1 | `[ ]` | `tests/test_obligations.py::test_parse` (to be written) | M1 |
| `protection.protect()` | RFC 9810 sec. 5.1.3 | `[ ]` | `tests/test_obligations.py::test_protect` (to be written) | M2 |
| `protection.verify_protection()` | RFC 9810 sec. 5.1.3 | `[ ]` | `tests/test_obligations.py::test_verify_protection` (to be written) | M2 |
| `crmf.build_request()` | RFC 4211 sec. 5 | `[ ]` | `tests/test_obligations.py::test_build_request` (to be written) | M3 |
| `flow.enroll()` | RFC 9810 | `[ ]` | `tests/test_obligations.py::test_enroll` (to be written) | M4 |
| `flow.poll_until_ready()` | RFC 9810 sec. 5.3.22 | `[ ]` | `tests/test_obligations.py::test_poll_until_ready` (to be written) | M4 |
| `est.simple_enroll()` | RFC 7030 sec. 4.2.1 | `[ ]` | `tests/test_obligations.py::test_simple_enroll` (to be written) | M5 |
| `est.ca_certs()` | RFC 7030 sec. 4.1 | `[ ]` | `tests/test_obligations.py::test_ca_certs` (to be written) | M5 |

## 2. Milestones

- M1 CMP message codec round trip against captured vendor traffic
- M2 protection both ways, with senderNonce replay tests
- M3 CRMF request building and proof of possession
- M4 the transaction state machine including poll and error responses
- M5 EST client and its two authentication modes
- M6 publication: 0.1.0 with interop notes against at least two CA implementations

Every milestone is accepted by its rows above flipping to `[ok]` with a named test, not by
the code existing. Coverage in `pyproject.toml` ratchets in the same commit.

## 3. Errata watch

- RFC 9810 already carries 4 verified errata as of 2026-11-07 (rfclib). Implement 9810, not the 4210 text that most tutorials still copy.
- RFC 7030 carries 3 verified errata and is updated by RFC 8951, RFC 8996 and RFC 9908.
- RFC 4211 carries 2 verified errata and is updated by RFC 9045. RFC 9811 obsoletes RFC 6712 and, with RFC 9810, RFC 9480.
- RFC 4210 is OBSOLETE: cite it only when explaining a legacy server.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| ACME, which acme already does well | `[no]` | a named document requires it |
| a CA or an RA: this is the client side of a conversation | `[no]` | a named document requires it |
| key generation policy: bring your own keys, or accept a hardware-backed signer through an interface | `[no]` | a named document requires it |

## 5. Open questions

- which section of RFC 9810 `flow.enroll()` is accepted against: the transaction spans the certification request, response and confirmation exchanges, so its Spec cell stays the bare RFC until that is decided

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
