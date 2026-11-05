# Specification completeness -- and the roadmap it implies

This is the project's north star: every protocol obligation enrollkit could plausibly take on,
with an honest status against the code at `HEAD`. It is blunt about gaps on purpose. A
roadmap that overstates its coverage is not a plan, it is marketing.

**The honesty rule:** a row may read `[ok]` only when a named test would fail if the
behaviour regressed. Reading the code and agreeing with it is not enough. That is how
"decoded but never sent" quietly becomes "implemented".

Legend: `[ok]` implemented and pinned by a named test -- `[part]` partial, with what is
missing stated -- `[ ]` not implemented -- `[no]` deliberate non-goal.

Update the affected row in the same commit that changes the behaviour. A row and its test
drift apart within one release, and the document becomes useless exactly when it is needed.

## 1. Obligations

| Obligation | Spec | Status | Where |
|---|---|---|---|
| `messages.build_cr()` | RFC 9810 | `[ ]` | `tests/test_obligations.py::build_cr` |
| `messages.parse()` | RFC 9810 | `[ ]` | `tests/test_obligations.py::parse` |
| `protection.protect()` | RFC 9810 | `[ ]` | `tests/test_obligations.py::protect` |
| `protection.verify_protection()` | RFC 9810 | `[ ]` | `tests/test_obligations.py::verify_protection` |
| `crmf.build_request()` | RFC 4211 | `[ ]` | `tests/test_obligations.py::build_request` |
| `flow.enroll()` | RFC 9810 | `[ ]` | `tests/test_obligations.py::enroll` |
| `flow.poll_until_ready()` | RFC 9810 | `[ ]` | `tests/test_obligations.py::poll_until_ready` |
| `est.simple_enroll()` | RFC 7030 | `[ ]` | `tests/test_obligations.py::simple_enroll` |
| `est.ca_certs()` | RFC 7030 | `[ ]` | `tests/test_obligations.py::ca_certs` |

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

- RFC 9810 already carries 4 verified errata eleven months after publication. Implement 9810, not the 4210 text that most tutorials still copy.
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

- none recorded yet

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented
