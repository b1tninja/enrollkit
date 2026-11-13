# enrollkit

<!-- PyPI badges go live with the first release. Until then a version badge renders
     "no version" on the landing page, which reads as a defect rather than a date, so
     the badges stay commented out until the tag exists.
-->

**Pre-alpha shell.** The package surface, the obligation matrix and the CI gates exist.
One behaviour is implemented, `messages.parse_header()` (RFC 9810 sec. 5.1.1); every other
public function raises `NotImplementedError`, and the test suite records that rather than hiding it. Read
[ROADMAP.md](ROADMAP.md) before depending on any of it.

enrollkit -- CMP and EST clients for private PKIs

CMP was rewritten in 2025-07. RFC 9810 obsoletes RFC 4210 and RFC 9480, replaces EncryptedValue with EnvelopedData and adds KEM key support, and it has already accumulated 4 verified errata. No Python library implements CMP at any revision, and EST, the simpler HTTPS enrollment profile, has none either. ACME is the well  served half, acme 5.9.0 shipped on 2026-10-29, and this project deliberately does not compete with it: private and enterprise PKIs run CMP and EST, and today that means openssl CLI invocations or a Java stack.

## The gap, with a date

PyPI was queried on 2026-11-05 for this name and for every neighbouring project. Landscape
claims rot quickly: two projects in this portfolio shipped within five days of the survey,
which is why the table below carries dates instead of adjectives.

| Project | Version | Last release | Why it is not this project |
|---|---|---|---|
| acme | 5.9.0 | 2026-10-29 | the ACME half, actively maintained; deliberately out of scope here |
| certipy | 0.2.3 | 2026-04-29 | Active Directory certificate services tooling, a different backend |
| cmp, crmf, cmpclient, enrollkit | - | - | cmp is a 2019 name squat, est belongs to a spectroscopy package, the rest are absent (2026-11-05) |

What this project intends to add:

- CMP message construction and parsing to RFC 9810, including the EnvelopedData change
- both protection mechanisms: shared secret MAC and signature based, with senderNonce replay discipline
- the full interaction set: IP, CP, CR, Kurt, poll, conf, p10cr, rblu and error handling
- EST client with /simpleEnroll, /cacerts and /curl plus HTTP Basic and TLS client authentication
- poll and pending flows, which is where real CA integrations actually break

## Specification spine

Status and publication dates below were read from the RFC Editor record on 2026-11-05. A
section number is cited only where that section was read in full; everything else cites the
document, which is the honest grain size for a plan. See [docs/rfc-map.md](docs/rfc-map.md).

| Document | Status | Published | What it gives this project |
|---|---|---|---|
| RFC 9810 | Proposed Standard | 2025-07 | current CMP: messages, protection, EnvelopedData, KEM support |
| RFC 9811 | Proposed Standard | 2025-07 | HTTP transfer for CMP, including the well-known URI prefix |
| RFC 9481 | Proposed Standard | 2023-11 | the algorithm set CMP must and may support |
| RFC 4211 | Proposed Standard | 2005-09 | CRMF: the certificate request message CMP carries |
| RFC 7030 | Proposed Standard | 2013-10 | EST: enrollment over HTTPS with CMC, plus CA certificate retrieval |
| RFC 9483 | Proposed Standard | 2023-11 | the lightweight CMP profile real industrial and IoT deployments implement |
| RFC 8951 | Proposed Standard | 2020-11 | EST clarification: base64 transfer, Content-Transfer-Encoding ignored |
| RFC 10002 | Proposed Standard | 2026-07 | CMC, current: obsoletes RFC 5272, which RFC 7030 still cites; EST `/cacerts` returns its certs-only response |

### Errata watch

- RFC 9810 already carries 4 verified errata as of 2026-11-07 (rfclib). Implement 9810, not the 4210 text that most tutorials still copy.
- RFC 7030 carries 3 verified errata and is updated by RFC 8951, RFC 8996 and RFC 9908.
- RFC 4211 carries 2 verified errata and is updated by RFC 9045. RFC 9811 obsoletes RFC 6712 and, with RFC 9810, RFC 9480.
- RFC 4210 is OBSOLETE: cite it only when explaining a legacy server.
- RFC 9483 carries 6 verified errata as of 2026-11-13, and RFC 5272 is OBSOLETE (RFC 10002); see [docs/rfc-map.md](docs/rfc-map.md).

## Module layout

| Module | Responsibility |
|---|---|
| `messages` | CMP PKIMessage and its body variants (RFC 9810, RFC 9811) |
| `protection` | POPOSIMESTAMP, POPOWITNESS and signature protection (RFC 9810) |
| `crmf` | request objects, keys and proof of possession (RFC 4211) |
| `flow` | the transaction state machine including poll and confirm |
| `est` | the HTTPS profile: simpleEnroll, cacerts and curl (RFC 7030) |
| `http` | bounded transport with retry and proxy awareness |
| `trust` | server authentication for enrollment endpoints, the part everyone bolts on |

## What it does not do

- ACME, which acme already does well
- a CA or an RA: this is the client side of a conversation
- key generation policy: bring your own keys, or accept a hardware-backed signer through an interface



## Why this project has a runtime dependency

CMP messages are deep ASN.1 inside CMS. Writing that schema layer again would be the third Python implementation of the same structures, so the definitions are written here, on asn1core, the portfolio's own DER codec that keeps the bytes it parsed. The `cryptography` package is used for cryptographic primitives only (signatures, MACs, AES) and never to read a wire format. What this project owns is the protocol: message order, protection, and recovery from the failures.

Declared as a floor with no ceiling: the application that installs this library resolves the final set, and a ceiling inside a library guarantees a conflict the first time something else needs a newer line.
## Install

```bash
git clone https://github.com/b1tninja/enrollkit.git
cd enrollkit
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\\Scripts\\Activate.ps1
pip install -e ".[dev]"
```

Not published to PyPI yet. The name is reserved for this repository's trusted publisher at
the moment of the first release.

## Development

All four gates must pass, on Linux and Windows alike:

```bash
ruff check . && ruff format --check .
mypy enrollkit tests
pytest -q --cov
python -O -m pytest -q
```

The last line is the one that matters most in a protocol library. `-O` strips `assert`, and a
parser whose bounds checks were asserts stops being a parser under production flags. Wire
paths raise named exceptions; asserts belong in tests and nowhere else.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
