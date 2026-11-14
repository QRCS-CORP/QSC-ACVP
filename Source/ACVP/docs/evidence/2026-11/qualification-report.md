# QSC: NIST ACVTS Demo Qualification Evidence

**Document ID:** QRCS-QSC-ACVTS-QR-2026-11-001  
**Issuer:** QRCS Corporation  
**Reporting period:** November 12-13, 2026 (America/Toronto); final UTC runs extend into November 14  
**Status:** 25 planned target sessions passed on the **NIST ACVTS Demo sample server**  
**Scope:** Technical algorithm-conformance evidence, **not** a NIST CAVP algorithm certificate or a FIPS 140-3/CMVP module validation

## Executive summary

QSC completed **25 independently authorized NIST ACVTS Demo sample sessions** covering **86 submitted algorithm vector sets**. Each archived client report contains `status: PASS_DEMO_SAMPLE` and `server_passed: true`. The qualification campaign covers SHA-2, SHA-3, SHAKE, HMAC, AES, PBKDF, ML-KEM, ML-DSA, SLH-DSA, HMAC_DRBG, KDA-HKDF, ECDSA, DetECDSA, EdDSA, XECDH and KAS-ECC-SSC, using the specifically registered implementations and operations.

**Evidence provenance:** The [machine-readable evidence manifest](evidence-manifest.json) records every NIST Demo session ID, vector-set ID, algorithm and operation, GitHub Actions URL, original sanitized artifact SHA-256, normalized JSON SHA-256 and tested source-cohort reference. The [original Actions artifacts](https://github.com/QRCS-CORP/QSC-ACVP/actions) have time-limited retention. QRCS preserved all 25 original artifact ZIPs separately in a controlled evidence archive.

## Source revision boundaries

Two immutable QSC source revisions were exercised. **These are two different tested source cohorts, not a claim that all 25 targets ran against a single current source commit.**

| Cohort | Targets | QSC source commit |
|---|---:|---|
| A: initial algorithm campaign | 18 | [`43c8aa2afe9d38c3ddf9bac0107196545981ac28`](https://github.com/QRCS-CORP/QSC/commit/43c8aa2afe9d38c3ddf9bac0107196545981ac28) |
| B: HCG, KDA and ECC extension | 7 | [`5d85f25866f9fa08654791265f08f43f95674a53`](https://github.com/QRCS-CORP/QSC/commit/5d85f25866f9fa08654791265f08f43f95674a53) |

The recorded source references were checked against the workflow files at each GitHub run head. Representative original checkout logs were also examined. See the manifest's `source_revision_note` for the precise verification boundary.

## Completed NIST Demo target sessions

| No. | Algorithm target | Session | Submitted vector sets | GitHub Actions run | Cohort |
|---:|---|---:|---:|---|---|
| 01 | SHA2-256 | 787624 | 1 | [43321340135](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43321340135) | A |
| 02 | SHA2-384 | 787625 | 1 | [43328100214](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43328100214) | A |
| 03 | SHA2-512 | 787626 | 1 | [43328944584](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43328944584) | A |
| 04 | SHA3-256 | 787627 | 1 | [43329645114](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43329645114) | A |
| 05 | SHA3-512 | 787637 | 1 | [43338490656](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43338490656) | A |
| 06 | SHAKE-128 | 787639 | 1 | [43339494189](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43339494189) | A |
| 07 | SHAKE-256 | 787641 | 1 | [43340356998](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43340356998) | A |
| 08 | HMAC-SHA2-256 | 787644 | 2 | [43341213710](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43341213710) | A |
| 09 | HMAC-SHA2-384 | 787646 | 2 | [43341894638](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43341894638) | A |
| 10 | HMAC-SHA2-512 | 787648 | 2 | [43342406504](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43342406504) | A |
| 11 | AES-ECB | 787654 | 1 | [43350776946](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43350776946) | A |
| 12 | AES-CBC | 787656 | 1 | [43351680223](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43351680223) | A |
| 13 | AES-CTR | 787664 | 1 | [43357212151](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43357212151) | A |
| 14 | AES-GCM | 787665 | 2 | [43359628131](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43359628131) | A |
| 15 | PBKDF | 787672 | 4 | [43361501531](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43361501531) | A |
| 16 | ML-KEM | 787673 | 6 | [43363695106](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43363695106) | A |
| 17 | ML-DSA | 787674 | 5 | [43365698700](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43365698700) | A |
| 18 | SLH-DSA | 787676 | 4 | [43367485294](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43367485294) | A |
| 19 | HMAC_DRBG-SHA2-512 | 787980 | 3 | [43501732560](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43501732560) | B |
| 20 | KDA-HKDF | 787994 | 9 | [43518311133](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43518311133) | B |
| 21 | ECDSA | 787996 | 8 | [43526926643](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43526926643) | B |
| 22 | DetECDSA | 787997 | 6 | [43534002049](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43534002049) | B |
| 23 | EDDSA | 788004 | 8 | [43537644321](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43537644321) | B |
| 24 | XECDH | 788040 | 6 | [43545312767](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43545312767) | B |
| 25 | KAS-ECC-SSC | 788041 | 9 | [43547438305](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43547438305) | B |

*The count is of 25 separately planned qualification targets, not 25 certificates. Many sessions repeat same-session prerequisite vector sets.*

## Detailed vector-set register

| Target | Session ID | Submitted NIST vector-set IDs (operation where supplied) |
|---|---:|---|
| SHA2-256 | 787624 | 4148700 |
| SHA2-384 | 787625 | 4148701 |
| SHA2-512 | 787626 | 4148702 |
| SHA3-256 | 787627 | 4148703 |
| SHA3-512 | 787637 | 4148741 |
| SHAKE-128 | 787639 | 4148744 |
| SHAKE-256 | 787641 | 4148747 |
| HMAC-SHA2-256 | 787644 | 4148782, 4148783 |
| HMAC-SHA2-384 | 787646 | 4148786, 4148787 |
| HMAC-SHA2-512 | 787648 | 4148790, 4148791 |
| AES-ECB | 787654 | 4148849 |
| AES-CBC | 787656 | 4148851 |
| AES-CTR | 787664 | 4148911 |
| AES-GCM | 787665 | 4148912, 4148913 |
| PBKDF | 787672 | 4148920, 4148921, 4148922, 4148923 |
| ML-KEM | 787673 | 4148924, 4148925, 4148926, 4148927, 4148928 (keyGen), 4148929 (encapDecap) |
| ML-DSA | 787674 | 4148930, 4148931, 4148932 (keyGen), 4148933 (sigGen), 4148934 (sigVer) |
| SLH-DSA | 787676 | 4148936, 4148937 (keyGen), 4148938 (sigGen), 4148939 (sigVer) |
| HMAC_DRBG-SHA2-512 | 787980 | 4151645, 4151646, 4151647 |
| KDA-HKDF | 787994 | 4151871, 4151872, 4151873, 4151874, 4151875, 4151876, 4151877, 4151878 (HKDF), 4151879 (HKDF) |
| ECDSA | 787996 | 4151888, 4151889, 4151890, 4151891, 4151892, 4151893 (keyGen), 4151894 (keyVer), 4151895 (sigVer) |
| DetECDSA | 787997 | 4151896, 4151897, 4151898, 4151899, 4151900, 4151901 (sigGen) |
| EDDSA | 788004 | 4151950, 4151951, 4151952, 4151953, 4151954 (keyGen), 4151955 (keyVer), 4151956 (sigGen), 4151957 (sigVer) |
| XECDH | 788040 | 4152263, 4152264, 4152265, 4152266 (keyGen), 4152267 (keyVer), 4152268 (SSC) |
| KAS-ECC-SSC | 788041 | 4152269, 4152270, 4152271, 4152272, 4152273, 4152274 (keyGen), 4152275 (keyVer), 4152276 (sigVer), 4152277 |

## Qualification evidence process

1. GitHub-hosted native QSC qualification checked out an immutable source reference as an external, read-only dependency.
2. The protected qualification client registered supported capabilities with **`isSample: true`** on NIST ACVTS Demo; one manually authorized server session per campaign stage.
3. Native QSC implementations processed the returned vectors and the qualification client submitted the responses to NIST.
4. The client recorded a sanitized final server verdict, test-session identifier and vector set metadata.
5. QRCS archived the downloaded original GitHub Actions result ZIPs, normalized JSON, recorded source references and SHA-256 integrity hashes.

**Integrity:** The separate evidence ZIP contains `SHA256SUMS.txt`, 25 byte-for-byte original Actions ZIPs, the normalized JSON records and a CSV index; the manifest here contains the individual original-artifact SHA-256 digests. A public GitHub source manifest alone is not a substitute for separately preserving the ZIPs.

## Reconciliation and known exceptions

- **SHA2-256 session 787624:** the first artifact records overall `server_passed: true` and `PASS_DEMO_SAMPLE`, but the intermediate `vector_verdict_statuses` is `["incomplete"]`. The original has been retained *without alteration*. Later independently submitted SHA2-256 prerequisite vectors, including sessions 787644 and 787994, record `["passed"]`. Consequently the successful SHA2-256 target is not supported solely by the anomalous early status field.
- **Two QSC source cohorts:** all results must be attributed to their exact tested source revisions, not to any future or different version of QSC.
- **Limits of evidence:** the reports are sanitized qualification-client outputs that summarize server verdicts. They are not NIST-signed algorithm certificates, full raw test vectors, complete test-response payloads or evidence of every operating-system/ISA build path.
- **Live CI vs offline CI:** the 25 test sessions are separate from the additional GitHub-hosted offline qualification suites. A green badge on this document reports the historical completed Demo campaign only, never the live CI state.
- **Artifact retention:** GitHub Actions artifacts and some run history may expire; QRCS separately archived the evidence and should maintain a second trusted backup.

## Public claim wording

> In November 2026, QRCS Corporation completed 25 planned algorithm-conformance targets against the NIST ACVTS Demo sample server. The completed campaign comprised 86 submitted vector sets over two source-pinned QSC revisions. The preserved qualification-client results report successful NIST server verdicts for each planned target. Full technical evidence, scope boundaries and source references are available in the QSC-ACVP repository.

**Do not describe this as NIST-certified QSC, FIPS 140-3 validated QSC, 25 CAVP certificates, or NIST endorsement.**

## Next steps toward formal validation

Formal CAVP qualification and publication are distinct from this sample campaign. Consult a qualified accredited testing laboratory to establish the production ACVTS requirements, security boundary, exact operating environment and algorithm capability set. The existing Demo results are engineering and readiness evidence, not a transfer-ready certificate.

## Primary references

- [NIST CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program)
- [NIST ACVP](https://pages.nist.gov/ACVP/)
- [NIST ACVP protocol](https://pages.nist.gov/ACVP/draft-fussell-acvp-spec.html)
- [QSC-ACVP qualification repository](https://github.com/QRCS-CORP/QSC-ACVP)

**Document control:** Issued by QRCS Corporation; November 2026. This document is limited to the NIST Demo evidence listed in the traceable machine-readable register.
