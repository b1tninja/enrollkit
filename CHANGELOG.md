# Changelog

The format follows Keep a Changelog, and this project adheres to Semantic Versioning.

## Unreleased

Nothing yet. This repository is a shell: the public surface exists as typed stubs that raise
`NotImplementedError`, and [ROADMAP.md](ROADMAP.md) lists what has to happen first.

### Added

- `messages.parse_header()`, `check_transaction_echo()` and `is_null_dn()`: PKIHeader parsing to RFC 9810 sec. 5.1.1, on asn1core.
- ROADMAP rows for the research findings, and the owner decisions D2, D3 and E1.

### Changed

- `asn1crypto` is no longer a dependency; asn1core replaces it, and `cryptography` stays for primitives only.

## 0.0.0 - 2026-11-05

### Added

- Package skeleton, obligation matrix and CI gates for enrollkit.
- `enrollkit.apps` namespace reserved for composition that is not protocol behaviour.
