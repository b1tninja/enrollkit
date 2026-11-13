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
| `messages.build_cr()` (a cr around a CertReqMessages: MAC-style sender commonName repeated as senderKID, recipient commonName or NULL-DN, fresh 128-bit transactionID and senderNonce, optional implicitConfirm and certProfile; unprotected until `protect`. The signature-protected sender, a name taken from a certificate subject, is not expressible by a string and stays with `build_header`) | RFC 9810 sec. 5.3.3; RFC 9483 sec. 3.1 | `[ok]` | `tests/test_build_cr_and_protection.py::test_build_cr`, `tests/test_build_cr_and_protection.py::test_build_cr_defaults_and_refusals` | M1 |
| `messages.parse()` | RFC 9810 sec. 5.1 | `[ok]` | `tests/test_flow.py::test_parse_splits_message_into_header_body_protection_and_extra_certs` | M1 |
| `messages.parse_header()` | RFC 9810 sec. 5.1.1 | `[ok]` | `tests/test_pkiheader.py::test_transaction_id_is_echoed_and_nonce_lengths_are_reported`, `tests/test_pkiheader.py::test_tag_order_violation_refused`, `tests/test_pkiheader.py::test_header_with_trailing_bytes_refused` | M1 |
| `messages.check_transaction_echo()` | RFC 9810 sec. 5.1.1 | `[ok]` | `tests/test_pkiheader.py::test_transaction_id_is_echoed_and_nonce_lengths_are_reported` | M1 |
| `messages.is_null_dn()` | RFC 9810 sec. 5.1.1 | `[ok]` | `tests/test_pkiheader.py::test_null_dn_sender_is_recognised` | M1 |
| `messages.header-build` | RFC 9810 sec. 5.1.1, sec. 7 | `[ok]` | `tests/test_profile_9483.py::test_build_header_round_trips` | M1 |
| `messages.header-9483` | RFC 9483 sec. 3.1 | `[ok]` | `tests/test_profile_9483.py::test_header_profile_rules`, `tests/test_profile_9483.py::test_header_profile_mac_sender_and_general_info` | M1 |
| `messages.vectors` | research | `[ ]` | `tests/test_vectors.py::test_independent_encoder_agrees` (to be written) | M1 |
| `protection.protect()` (shared-secret protection: rebuilds the header with protectionAlg, keeps an existing protectionAlg byte for byte, MACs the ProtectedPart with PBM, PBMAC1 or AES-GMAC, keeps extraCerts; default PBM SHA-256, HMAC-SHA256, 10,000 iterations, fresh salt; reproduces the protection and header bytes of four OpenSSL 3.5.6 requests; signature protection is `protection.signature`) | RFC 9810 sec. 5.1.1, sec. 5.1.3.1 | `[ok]` | `tests/test_build_cr_and_protection.py::test_protect_reproduces_the_openssl_protection`, `tests/test_build_cr_and_protection.py::test_protect`, `tests/test_build_cr_and_protection.py::test_protect_with_pbmac1_and_gmac` | M2 |
| `protection.verify_protection()` (the second argument is now the shared secret, not a `Trust`: recomputes the MAC over the received header and body, constant-time; refuses missing protection, protection without protectionAlg and the reverse, a flipped bit anywhere and a wrong secret with `ProtectionError`; a signature algorithm raises `NotImplementedError` and never passes; the trust-anchored signature check is `protection.signature`) | RFC 9810 sec. 5.1.1, sec. 5.1.3.1 | `[ok]` | `tests/test_build_cr_and_protection.py::test_verify_protection_follows_the_key_rule`, `tests/test_build_cr_and_protection.py::test_verify_protection_refuses_what_does_not_verify`, `tests/test_build_cr_and_protection.py::test_verify_protection_never_passes_a_signature_algorithm` | M2 |
| `protection.pbm` | RFC 4211, RFC 9045, RFC 9481 | `[part]` | `tests/test_protection.py::test_pbm_known_answer`, `tests/test_protection.py::test_pbm_algorithm_identifier_round_trips_and_policy` | M2 |
| `protection.nonce-replay` | RFC 9810 sec. 5.1.1 | `[ ]` | `tests/test_protection.py::test_recip_nonce_must_echo_sender_nonce` (to be written) | M2 |
| `crmf.build_request()` | RFC 4211 sec. 5 | `[ ]` | `tests/test_obligations.py::test_build_request` (to be written) | M3 |
| `crmf.pop` | RFC 4211, RFC 9810 sec. 4.3 | `[part]` | `tests/test_crmf.py::test_proof_of_possession_verifies`, `tests/test_crmf.py::test_pop_refuses_tampering_wrong_key_and_missing_pieces` | M3 |
| `flow.enroll()` | RFC 9810 | `[ ]` | `tests/test_obligations.py::test_enroll` (to be written) | M4 |
| `flow.poll_until_ready()` | RFC 9810 sec. 5.3.22 | `[ ]` | `tests/test_obligations.py::test_poll_until_ready` (to be written) | M4 |
| `flow.ir_cr_exchange` | RFC 9810 sec. 5.3.1 to 5.3.4 | `[ok]` | `tests/test_flow.py::test_ir_ip_exchange`, `tests/test_flow.py::test_exchange_refuses_wrong_echo_and_wrong_body`, `tests/test_flow.py::test_exchange_waiting_rejection_and_error` | M4 |
| `flow.confirm` | RFC 9810 sec. 5.3.18, sec. 5.1.1.1 | `[part]` | `tests/test_flow.py::test_implicit_confirm_skips_certconf_only_when_granted` | M4 |
| `flow.errors` | RFC 9810 sec. 5.3.21 | `[part]` | `tests/test_flow.py::test_exchange_waiting_rejection_and_error` | M4 |
| `http.cmp` | RFC 9811 | `[ ]` | `tests/test_http.py::test_well_known_cmp_uri` (to be written) | M4 |
| `est.simple_enroll()` | RFC 7030 sec. 4.2.1 | `[ ]` | `tests/test_obligations.py::test_simple_enroll` (to be written) | M5 |
| `est.ca_certs()` | RFC 7030 sec. 4.1, RFC 8951 sec. 3 | `[ ]` | `tests/test_obligations.py::test_ca_certs` (to be written) | M5 |
| `est.cms_response` | RFC 7030 sec. 4.1.3, RFC 8951 sec. 3, RFC 10002 sec. 4.1, RFC 5652 | `[ok]` | `tests/test_est_cacerts.py::test_response_accepts_missing_content_transfer_encoding`, `tests/test_est_cacerts.py::test_response_refuses_what_is_not_a_certs_only_response` | M5 |
| `est.cacerts-parse` | RFC 7030 sec. 4.1.3: `est.cacerts_response` unwraps the certs-only SignedData through signeddata and parses each certificate with asn1core; choosing the TA and the Root CA Key Update certificates is `trust.explicit_ta` | `[ok]` | `tests/test_est_cacerts.py::test_cacerts_response_parses_each_certificate_with_asn1core` | M5 |
| `est.csrattrs` | RFC 7030 sec. 4.5, RFC 9908 | `[ ]` | `tests/test_est_csrattrs.py::test_attr_or_oid_choice_parses` (to be written) | M5 |
| `est.serverkeygen` | RFC 7030 sec. 4.4 | `[ ]` | `tests/test_est_serverkeygen.py::test_multipart_response` (to be written) | M5 |
| `trust.explicit_ta` | RFC 7030 sec. 4.1.3 | `[ ]` | `tests/test_trust.py::test_cacerts_become_explicit_ta` (to be written) | M5 |
| `messages.build_message` | RFC 9810 sec. 5.1 | `[part]` | `tests/test_flow.py::test_parse_splits_message_into_header_body_protection_and_extra_certs` | M1 |
| `messages.body-readers` | RFC 9810 sec. 5.3 | `[part]` | `tests/test_flow.py::test_ir_ip_exchange` | M1 |
| `messages.body-builders` | RFC 9810 sec. 5.3.1 to 5.3.4, 5.3.18, 5.3.21, 5.3.22: `bodies` builds the contents of ir, cr, kur and ccr (`cert_req_messages_content`), p10cr, certConf (`cert_status`, `cert_conf_content`, `cert_hash` by the signature algorithm, RFC 9481 sec. 3.3 for EdDSA), pollReq, pollRep and error, and reads certConf, pollReq, pollRep, error and PKIStatusInfo back. Not done: a reader for CertReqMessages (a server's job), builders for ip, cp and kup | `[part]` | `tests/test_messages_bodies.py::test_ir_cr_certconf_pollreq_round_trip`, `tests/test_messages_bodies.py::test_cert_status_info_and_hash_alg_are_read_back`, `tests/test_messages_bodies.py::test_failure_info_is_a_dernamed_bit_string`, `tests/test_messages_bodies.py::test_error_message_content_and_its_waiting_status`, `tests/test_messages_bodies.py::test_cert_hash_follows_the_signature_algorithm` | M1 |
| `protection.pbm-external-vector` | RFC 4211 sec. 4.4: four `ir` requests written by `openssl cmp -reqout_only` (OpenSSL 3.5.6) in `tests/vectors/openssl-3.5.6-cmp-ir-pbm.json` verify under `pbm_verify`. They verify with the key rule `KEY_BASEKEY`, and under the default RFC 9810 rule only when the OWF and the HMAC hash have the same size (row `protection.pbm-hmac-key-length`) | `[ok]` | `tests/test_protection.py::test_pbm_matches_openssl_capture` | M2 |
| `protection.pbm-hmac-key-length` | RFC 9810 sec. 5.1.3.1: a second implementation now exists and disagrees. OpenSSL 3.5.6 keys the HMAC with the whole BASEKEY, with no truncation (HMAC-SHA1 under a SHA-256 OWF) and no expansion (HMAC-SHA256 under a SHA-1 OWF); this package's default reads K as the HMAC output size, per the RFC text. `pbm_key(rule=KEY_BASEKEY)` is OpenSSL's reading; the default is unchanged. Owner decision needed: which one is the default for verifying and for sending (a sender that expands will not be understood by OpenSSL peers, and the converse) | `[part]` | `tests/test_protection.py::test_rfc9810_key_rule_agrees_with_openssl_only_when_the_sizes_match`, `tests/test_protection.py::test_pbm_known_answer` | M2 |
| `protection.pbmac1-gmac` | RFC 9045 sec. 4.4, RFC 9481 sec. 6.1.2 and 6.2.2, RFC 8018 sec. 7.1: `Pbmac1Parameter` with `pbmac1_key`, `pbmac1_mac`, `pbmac1_verify` (PBKDF2 and HMAC, checked against `openssl kdf` and `openssl mac`; DER omits the default PRF; a missing keyLength is refused by this library's policy), `GmacParameter` with `gmac_mac` for a shared-key protectionAlg (checked against `openssl mac ... GMAC`), and PBM with AES-GMAC as its mac (`PbmParameter.mac_nonce`). Wired into `protect()` and `verify_protection()` (`tests/test_build_cr_and_protection.py::test_protect_with_pbmac1_and_gmac`) | `[ok]` | `tests/test_protection.py::test_pbmac1_and_aes_gmac`, `tests/test_protection.py::test_pbmac1_algorithm_identifier_bytes_and_default_prf`, `tests/test_protection.py::test_pbmac1_refusals`, `tests/test_protection.py::test_aes_gmac_matches_openssl`, `tests/test_protection.py::test_aes_gmac_parameters_follow_der_defaults_and_refuse_bad_input`, `tests/test_protection.py::test_pbm_with_aes_gmac_as_the_mac` | M2 |
| `protection.signature` | RFC 9810 sec. 5.1.3.3, RFC 9481 sec. 3 | `[ ]` | `tests/test_protection.py::test_signature_protection_round_trip` (to be written) | M2 |
| `crmf.pop-cases-1-2` | RFC 4211 sec. 4.1 | `[ ]` | `tests/test_crmf.py::test_poposk_input_with_sender_and_publickeymac` (to be written) | M3 |
| `crmf.pop-key-encipherment` | RFC 4211 sec. 4.2, 4.3, RFC 9810 sec. 5.2.8 | `[ ]` | `tests/test_crmf.py::test_encr_cert_and_challenge_response` (to be written) | M3 |
| `crmf.template-fields` | RFC 4211 sec. 5 | `[ ]` | `tests/test_crmf.py::test_template_extensions_and_controls` (to be written) | M3 |
| `flow.pollreq` | RFC 9810 sec. 5.3.22 and 5.3.21 para 4: `IrCrExchange` names the certReqIds of the CertResponses still waiting (`poll_request_ids`), or -1 after an `error` with status waiting; reads each pollRep, keeps the longest checkAfter and refuses a `poll_sent(now=)` that comes sooner; `bodies.poll_req_content` and `poll_rep_content` write the bodies. Not done: the timer and the transport, which are `flow.poll_until_ready` | `[ok]` | `tests/test_flow.py::test_poll_request_and_response_bodies`, `tests/test_flow.py::test_error_with_status_waiting_starts_polling_for_the_whole_response`, `tests/test_flow.py::test_a_pollrep_must_answer_a_pollreq_and_be_well_formed` | M4 |
| `est.cacerts-validation` | RFC 7030 sec. 4.1.3 | `[ ]` | `tests/test_est_cacerts.py::test_root_validated_out_of_band_before_chain` (to be written) | M5 |
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

## 9. Research findings, round 2 (2026-11-13)

| Finding | Evidence | Row |
|---|---|---|
| RFC 4211 sec. 4.1 case 3 prints "DER-encoded certificate template"; verified erratum 4797 makes the signature cover the DER `certReq` (the CertRequest). `crmf.sign_pop` signs `certReq` and the test verifies the bytes with `cryptography` directly | `errata('RFC4211')`, `tests/test_crmf.py::test_proof_of_possession_verifies` | `crmf.pop` |
| RFC 9045 changes PBM requirements: SHA-256 is the MUST OWF, HMAC-SHA256 the MUST MAC, iterationCount minimum stays 100 with 10,000 advised, the password SHOULD NOT be reused; AES-GMAC 128 with a 16-octet tag is a SHOULD. RFC 9045 has no errata | `read('RFC9045§4')`, `errata('RFC9045')` | `protection.pbm` |
| RFC 9810 sec. 5.1.3.1 MUST-requires the key expansion `BASEKEY, then OWF("1" concatenated with BASEKEY), and so on` when K > H, but neither it nor RFC 4211 or 9045 says what K is for HMAC. `pbm_key` takes K as the MAC hash's output size; no second implementation has confirmed it | `read('RFC9810§5.1.3.1')` | `protection.pbm-hmac-key-length` |
| RFC 9483 sec. 3.1: pvno 3 only where EnvelopedData is used or a certConf carries hashAlg, else 2; protectionAlg, transactionID and senderNonce REQUIRED; transactionID and senderNonce exactly 128 bits; recipNonce absent in the first message; implicitConfirm prohibited outside ir/cr/kur/p10cr and ip/cp/kup; certProfile only in ir/cr/kur/p10cr and genm. `check_header_9483` implements every one that needs no certificate | `read('RFC9483§3.1')` | `messages.header-9483` |
| CMP generalInfo OIDs, from RFC 9810 sec. 5.1.1.1, 5.1.1.2, 5.1.1.4 (id-it 13, 14, 21; id-it is id-pkix 4) | `grep('RFC9810', 'id-it-')` | `messages.header-build` |
| `signeddata.cms.certificates_only` and `cms.load` exist, so `est.cms_response` stands on them; enrollkit now resolves `../signeddata` by sibling path as it does asn1core | `signeddata/signeddata/cms.py` | `est.cms_response` |
| `pyproject.toml` pins `cryptography>50.0.2` while the interpreter here has 46.0.7 installed; the suite passes on it. Someone should confirm the pin is intended | `python -c "import cryptography"` | none |
| OpenSSL 3.5.6 keys the PBM HMAC with the whole BASEKEY and never expands or truncates; RFC 9810 sec. 5.1.3.1 reads K as a key size, which for HMAC it does not define. The two agree only when OWF and HMAC hash sizes are equal. The three disagreeing captures are in `tests/vectors/openssl-3.5.6-cmp-ir-pbm.json` | `tests/test_protection.py::test_rfc9810_key_rule_agrees_with_openssl_only_when_the_sizes_match` | `protection.pbm-hmac-key-length` |
| RFC 9810 sec. 5.3.22 (the second state-machine example, step 5) says an error message with status waiting has "certReqId set to -1", but ErrorMsgContent (sec. 5.3.21) has no certReqId. The -1 belongs to the pollReq that follows (sec. 5.3.22 item 1: the certReqId is an index or -1 for the complete response) | `read('RFC9810§5.3.21')`, `read('RFC9810§5.3.22')` | `flow.pollreq` |
| RFC 9481 sec. 3.3 para 7: certHash is SHA-512 for an Ed25519 certificate and SHAKE256 with d=512 (64 octets) for Ed448, so `cert_hash` cannot be a plain digest-size lookup | `read('RFC9481§3.3')` | `messages.body-builders` |
| RFC 8018 keyLength is OPTIONAL in PBKDF2-params, and no CMP document says what an HMAC key length is when it is absent; RFC 9579 sec. 5 (PKCS #12, obsolete by RFC 9879) makes it a MUST. This library requires it for PBMAC1 | `read('RFC9579§5')` | `protection.pbmac1-gmac` |
