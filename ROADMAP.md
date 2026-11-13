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
| `messages.parse_header()` | RFC 9810 sec. 5.1.1 | `[ok]` | `tests/test_pkiheader.py::test_transaction_id_is_echoed_and_nonce_lengths_are_reported`, `tests/test_pkiheader.py::test_tag_order_violation_refused`, `tests/test_pkiheader.py::test_header_with_trailing_bytes_refused` | M1 |
| `messages.check_transaction_echo()` | RFC 9810 sec. 5.1.1 | `[ok]` | `tests/test_pkiheader.py::test_transaction_id_is_echoed_and_nonce_lengths_are_reported` | M1 |
| `messages.is_null_dn()` | RFC 9810 sec. 5.1.1 | `[ok]` | `tests/test_pkiheader.py::test_null_dn_sender_is_recognised` | M1 |
| `messages.header-build` | RFC 9810 sec. 5.1.1, sec. 7 | `[ ]` | `tests/test_pkiheader.py::test_build_header_round_trips` (to be written) | M1 |
| `messages.header-9483` | RFC 9483 sec. 3.1 | `[ ]` | `tests/test_profile_9483.py::test_header_profile_rules` (to be written) | M1 |
| `messages.vectors` | research | `[ ]` | `tests/test_vectors.py::test_independent_encoder_agrees` (to be written) | M1 |
| `protection.protect()` | RFC 9810 sec. 5.1.3 | `[ ]` | `tests/test_obligations.py::test_protect` (to be written) | M2 |
| `protection.verify_protection()` | RFC 9810 sec. 5.1.3 | `[ ]` | `tests/test_obligations.py::test_verify_protection` (to be written) | M2 |
| `protection.pbm` | RFC 4211, RFC 9045, RFC 9481 | `[ ]` | `tests/test_protection.py::test_pbm_known_answer` (to be written) | M2 |
| `protection.nonce-replay` | RFC 9810 sec. 5.1.1 | `[ ]` | `tests/test_protection.py::test_recip_nonce_must_echo_sender_nonce` (to be written) | M2 |
| `crmf.build_request()` | RFC 4211 sec. 5 | `[ ]` | `tests/test_obligations.py::test_build_request` (to be written) | M3 |
| `crmf.pop` | RFC 4211, RFC 9810 sec. 4.3 | `[ ]` | `tests/test_crmf.py::test_proof_of_possession_verifies` (to be written) | M3 |
| `flow.enroll()` | RFC 9810 | `[ ]` | `tests/test_obligations.py::test_enroll` (to be written) | M4 |
| `flow.poll_until_ready()` | RFC 9810 sec. 5.3.22 | `[ ]` | `tests/test_obligations.py::test_poll_until_ready` (to be written) | M4 |
| `flow.ir_cr_exchange` | RFC 9810 sec. 5.3.1 to 5.3.4 | `[ ]` | `tests/test_flow.py::test_ir_ip_exchange` (to be written) | M4 |
| `flow.confirm` | RFC 9810 sec. 5.3.18, sec. 5.1.1.1 | `[ ]` | `tests/test_flow.py::test_certconf_unless_implicit_confirm_granted` (to be written) | M4 |
| `flow.errors` | RFC 9810 sec. 5.3.21 | `[ ]` | `tests/test_flow.py::test_error_message_is_surfaced` (to be written) | M4 |
| `http.cmp` | RFC 9811 | `[ ]` | `tests/test_http.py::test_well_known_cmp_uri` (to be written) | M4 |
| `est.simple_enroll()` | RFC 7030 sec. 4.2.1 | `[ ]` | `tests/test_obligations.py::test_simple_enroll` (to be written) | M5 |
| `est.ca_certs()` | RFC 7030 sec. 4.1, RFC 8951 sec. 3 | `[ ]` | `tests/test_obligations.py::test_ca_certs` (to be written) | M5 |
| `est.cms_response` | RFC 7030 sec. 4.1.3, RFC 8951 sec. 3, RFC 10002 sec. 4.1, RFC 5652 | `[ ]` | `tests/test_est_cacerts.py::test_response_accepts_missing_content_transfer_encoding` (to be written) | M5 |
| `est.csrattrs` | RFC 7030 sec. 4.5, RFC 9908 | `[ ]` | `tests/test_est_csrattrs.py::test_attr_or_oid_choice_parses` (to be written) | M5 |
| `est.serverkeygen` | RFC 7030 sec. 4.4 | `[ ]` | `tests/test_est_serverkeygen.py::test_multipart_response` (to be written) | M5 |
| `trust.explicit_ta` | RFC 7030 sec. 4.1.3 | `[ ]` | `tests/test_trust.py::test_cacerts_become_explicit_ta` (to be written) | M5 |
| `signer.interface` | design | `[ ]` | `tests/test_signer.py::test_callable_signer_is_the_only_key_access` (to be written) | M2 |

## 2. Milestones

- M1 CMP message codec round trip against an independent encoder (see `messages.vectors`; no vendor capture is named yet)
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
- RFC 9483 (Lightweight CMP Profile) carries 6 verified errata as of 2026-11-13 (rfclib): eids 7833 (sec. 4.1.6), 8183 (4.1.6.1), 8184 (4.1.6.2), 8663 and 8806 (4.1.4), 9052 (4.2, CRL reason code is not mandatory). None is on sec. 3.1, which `messages.header-9483` uses.
- RFC 9810 verified erratum 9044 amends sec. 5.1.1: the senderKID requirement for the NULL-DN sender applies only when the sender protects with a shared secret. Implement the corrected text.
- RFC 5272, which RFC 7030 sec. 4.1.3 and RFC 8951 sec. 3.2.1 still cite for the certs-only response, is OBSOLETE: RFC 10002 (2026-07) obsoletes it and RFC 6402. Cite 10002 for the current text and 5272 only as the reference 7030 makes.

## 4. Deliberate non-goals

| Non-goal | Status | Revisit when |
|---|---|---|
| ACME, which acme already does well | `[no]` | the owner decides D3 in section 7: PORTFOLIO sec. 6 draws an ACME arrow from this project |
| a CA or an RA: this is the client side of a conversation | `[no]` | a named document requires it |
| key generation policy: bring your own keys, or accept a hardware-backed signer through an interface | `[no]` | a named document requires it |

## 5. Open questions

- which section of RFC 9810 `flow.enroll()` is accepted against: the transaction spans the certification request, response and confirmation exchanges, so its Spec cell stays the bare RFC until that is decided. Proposed answer, not applied: `flow.enroll()` composes the three rows `flow.ir_cr_exchange`, `flow.confirm` and `flow.poll_until_ready()`, and is accepted by their tests rather than by a section of its own
- which captured or independently generated corpus M1 is checked against (`messages.vectors`): OpenSSL `cmp` and an independent CMP implementation are candidates; RFC 9810 Appendices C and D give message profiles, not encoded messages (the header tests here say where each fixture came from)

## 6. Publication checklist

- [ ] every `[ ]` row above either `[ok]` or moved to a named later milestone
- [ ] `docs/research.md` claims re-verified and the dated ones either promoted or deleted
- [ ] interoperability evidence recorded in `docs/` against a non-Python implementation
- [ ] `tools/check_dist.py` proves the wheel ships the fixtures the README promises
- [ ] version 0.1.0 tagged, trusted publisher configured, README badges uncommented

## 7. Owner decisions

Written for the owner to answer. Nothing here is chosen by the agent that wrote it.

### D3: ACME, both options

PORTFOLIO sec. 6 draws `enrollkit --> (ACME, RFC 8555)`; section 4 above lists ACME as a non-goal, and README says the project "deliberately does not compete with" the acme package. One of the two statements has to change.

- **Option A, enrollkit stays CMP and EST only.** Keep the non-goal. Remove the `(ACME, RFC 8555)` arrow from PORTFOLIO sec. 6 and record the decision in PORTFOLIO sec. 10. Cost: nothing here changes; a user who wants ACME uses the existing acme package, and the README survey table keeps naming acme as the neighbour it is.
- **Option B, enrollkit grows an ACME client.** Delete the non-goal row, keep the arrow, and add ACME rows (RFC 8555 carries 12 verified errata as of 2026-11-13 per the group A review; re-check with `errata('RFC8555')` before writing any row). Cost: a third protocol with its own account-key, JWS and challenge machinery, a public surface that competes with a maintained package, and a README gap statement that stops being true.

### D2 (shared with pgpenv): the Tier 4 / Wave 5 waiver

`docs/plan.md` says no obligation is taken while two projects are open. The header rows above were implemented under the fan-out instruction of 2026-11-13; whether that stands as a waiver is the owner's call, and the remaining rows wait on it.

### E1: signing is allowed, so the "signer callback" premise needs a ruling

The group A review proposed that enrollkit only accept a signer callback because the portfolio refuses to write signing. The 2026-11-13 instruction admits `cryptography` for RSA and ECDSA primitives, so `protection.protect()` may sign with it. `signer.interface` is kept for the hardware-backed case already named in the key-generation non-goal. Confirm that reading.

## 8. Research findings (2026-11-13)

| Finding | Evidence | Row |
|---|---|---|
| `asn1crypto` removed from `pyproject.toml`; message definitions are ours on asn1core | `tests/test_dependency_rule.py` | `messages.parse_header()` |
| EST `/cacerts` is a certs-only CMC Simple PKI Response, which is a CMS SignedData with no signers, so enrollkit depends on signeddata (its `cms.load` is a stub today) | RFC 7030 sec. 4.1.3 para 2; RFC 10002 sec. 2 | `est.cms_response` |
| RFC 8951 sec. 3: base64 body, any Content-Transfer-Encoding header MUST be ignored, whitespace SHOULD be tolerated | RFC 8951 sec. 3 and 3.1; RFC 7030 erratum 5904 | `est.cms_response` |
| RFC 5272 is OBSOLETE (RFC 10002); the group A review did not notice | `info('RFC5272')` | `est.cms_response` |
| RFC 9483 is the profile real deployments speak and was absent from the spine; sec. 3.1 sets header rules stricter than RFC 9810 (pvno 2 or 3, 128-bit transactionID and senderNonce, protectionAlg REQUIRED) | `read('RFC9483§3.1')` | `messages.header-9483` |
| RFC 9483 sec. 3.1 cites RFC 9480 for version negotiation; RFC 9480 is now obsoleted by RFC 9810 and RFC 9811, so the citation maps to RFC 9810 sec. 7 | `info('RFC9811')` | `messages.header-9483` |
| RFC 9810 sec. 5.1.1: nonce and transactionID sizes are recommendations, not receiver-enforced minimums; the parser reports short values and refuses none | `read('RFC9810§5.1.1')` | `messages.parse_header()` |
| RFC 7030 sec. 4.1.3 still cites RFC 4210 sec. 4.4 for Root CA Key Update; RFC 9810 sec. 4.4 is titled "Root CA Key Update" | `outline('RFC9810')` | `est.cms_response` |
| The review left pvno cmp2021 as unconfirmed; RFC 9810 sec. 5.1.1 gives cmp2021(3) | `read('RFC9810§5.1.1')` | `messages.parse_header()` |
