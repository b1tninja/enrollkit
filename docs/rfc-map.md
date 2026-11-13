# Where every claim in this repository comes from

| Document | Status | Published | Verified against the publisher record on |
|---|---|---|---|
| RFC 9810 | Proposed Standard | 2025-07 | 2026-11-05 |
| RFC 9811 | Proposed Standard | 2025-07 | 2026-11-05 |
| RFC 9481 | Proposed Standard | 2023-11 | 2026-11-05 |
| RFC 4211 | Proposed Standard | 2005-09 | 2026-11-05 |
| RFC 7030 | Proposed Standard | 2013-10 | 2026-11-05 |
| RFC 9483 | Proposed Standard | 2023-11 | 2026-11-13 |
| RFC 9045 | Proposed Standard | 2021-06 | 2026-11-13 |
| RFC 8951 | Proposed Standard | 2020-11 | 2026-11-13 |
| RFC 9908 | Proposed Standard | 2026-01 | 2026-11-13 |
| RFC 8996 | Best Current Practice (BCP 195) | 2021-03 | 2026-11-13 |
| RFC 10002 | Proposed Standard | 2026-07 | 2026-11-13 |
| RFC 5272 | Proposed Standard, OBSOLETE (RFC 10002) | 2008-06 | 2026-11-13 |
| RFC 5652 | Internet Standard (STD 70) | 2009-09 | 2026-11-13 |
| RFC 2986 | Informational | 2000-11 | 2026-11-13 |
| RFC 4210 | Proposed Standard, OBSOLETE (RFC 9810) | 2005-09 | legacy citations only |

Citation rules, in the order they most often get broken:

1. Cite the document. A secondary write-up is a lead, not a source.
2. A section number is cited only if that section was read in full.
3. Errata are checked at each milestone freeze, not once at the start.
4. Where a claim came from a body outside the RFC series, that body is named here.

Re-verify with the RFC library rather than memory: `info('RFCnnnn')` for current status, `errata('RFCnnnn')` for corrections, and `read('RFCnnnn', view='normative')` for the MUST and SHOULD statements that become obligation rows.

## Status, errata and relationships (rfclib, 2026-11-13)

| Document | Relationship | Verified errata | Used for |
|---|---|---|---|
| RFC 9810 | obsoletes RFC 4210 and RFC 9480; updates RFC 5912 | 4 (8682, 8683, 8684, 9044; 9044 is on sec. 5.1.1) plus 1 held (9051) | CMP messages, header, protection, flow |
| RFC 9811 | obsoletes RFC 6712 and, with RFC 9810, RFC 9480 | none | CMP over HTTP, `http.cmp` |
| RFC 9483 | none | 6 (7833, 8183, 8184, 8663, 8806, 9052), none on sec. 3.1 | lightweight profile, `messages.header-9483` |
| RFC 9481 | updates RFC 4210 although that is obsolete | 1 (7800, editorial) plus 1 held | algorithm set |
| RFC 4211 | updated by RFC 9045 | 2 | CRMF |
| RFC 9045 | updates RFC 4211 | none | password-based MAC requirements |
| RFC 7030 | updated by RFC 8951, RFC 8996, RFC 9908 | 3 (5904, 5926, 8399) plus 4 held, 1 rejected | EST |
| RFC 8951 | updates RFC 7030 | none | base64 body, header ignored, whitespace tolerated |
| RFC 9908 | updates RFC 7030 and RFC 9148 | none verified (1 on file) | CSR attributes |
| RFC 8996 | updates RFC 7030 among many | 2 | TLS 1.0 and 1.1 deprecated for EST transport |
| RFC 10002 | obsoletes RFC 5272 and RFC 6402 | none verified (2 on file) | CMC Simple PKI Response, the certs-only form EST returns |
| RFC 5272 | obsoleted by RFC 10002 | 5 | cited by RFC 7030 and RFC 8951; read RFC 10002 instead |
| RFC 5652 | updated by RFC 8933, RFC 9629 | 2 | the SignedData a certs-only response is; consumed through signeddata |
| RFC 2986 | updated by RFC 5967 | 2 | PKCS#10 request carried by EST simple enrollment |

### Corrections to earlier statements

- The group A review and the README said the CMC reference for `/cacerts` is RFC 5272. RFC 7030 does cite it, but RFC 5272 is now OBSOLETE; RFC 10002 is the current document.
- RFC 9483 was missing from this map and is the profile deployments implement.
- RFC 7030 cites RFC 4210 sec. 4.4 for the Root CA Key Update certificates; RFC 9810 sec. 4.4 carries that subject today.
- RFC 9483 sec. 3.1 cites RFC 9480 for version negotiation; RFC 9480 is obsoleted by RFC 9810 and RFC 9811, and RFC 9810 sec. 7 is the current text.
