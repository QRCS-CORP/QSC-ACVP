# QSC Offline Qualification Evidence Report

**Initial 13-stage campaign — verified completion record**

| Document control | Value |
| --- | --- |
| Organization | Quantum Resistant Cryptographic Solutions Corporation |
| Reporting date | 2026-11-11 (UTC) |
| Repository | [QRCS-CORP/QSC-ACVP](https://github.com/QRCS-CORP/QSC-ACVP) |
| Qualified source snapshot | [QSC `43c8aa2afe9d38c3ddf9bac0107196545981ac28`](https://github.com/QRCS-CORP/QSC/commit/43c8aa2afe9d38c3ddf9bac0107196545981ac28) |
| Campaign | GitHub-hosted, manually dispatched offline implementation prequalification |
| Reviewed result | **13 of 13 designated stages completed successfully** |
| NIST ACVTS / CAVP status | **Not run; no algorithm validation certificate claimed** |
| FIPS 140-3 validation | **Not performed** |

## Executive assessment

All thirteen designated offline qualification stages were independently reviewed against GitHub Actions job outcomes, selected test logs, and uploaded evidence artifacts. The fixed QSC source snapshot completed the planned coverage across Linux x64 scalar and AVX2, Windows x64 MSVC AVX2, Linux ARM64 cryptographic extensions, and macOS Apple Silicon ARM64. The scoped functional work includes SHA/HMAC, XOF, PBKDF/HKDF and AES bootstraps; FIPS 203 ML-KEM; FIPS 204 ML-DSA; FIPS 205 SLH-DSA SHAKE parameter sets; and selected elliptic-curve interoperability.

**Conclusion:** the initial **offline prequalification campaign** is complete for the named QSC source snapshot and specific selected environments. Passing these checks does **not** establish complete algorithm conformance, exhaustive instruction-path coverage, NIST algorithm validation, or FIPS 140-3 certification.

## Verified run and evidence register

Each link opens the actual GitHub Actions execution. Each named artifact was confirmed present and unexpired during report preparation. The artifacts contain the run's own sanitized logs, configuration information, machine-code evidence where applicable, and a fail-closed `run-manifest.json`.

| Stage | Operating environment / ISA | Tested scope | Verified result | Uploaded evidence artifact |
| --- | --- | --- | --- | --- |
| 01 | Linux x64 · scalar | SHA/HMAC, XOF, KDF, AES bootstrap | [OFFLINE_SMOKE_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42905877018) | `qsc-acvp-linux-x64-scalar-offline` |
| 02 | Linux x64 · AVX2/AES-NI | Accelerated SHA/HMAC, XOF, KDF, AES bootstrap | [OFFLINE_SMOKE_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42913130713) | `qsc-acvp-linux-x64-avx2-aesni-offline` |
| 03 | Windows x64 · MSVC AVX2 | Windows SHA/HMAC, XOF, KDF, AES bootstrap | [OFFLINE_SMOKE_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42914925220) | `qsc-acvp-windows-msvc-avx2-offline` |
| 04 | Linux ARM64 · crypto/NEON | ARM64 SHA/HMAC, XOF, KDF, AES bootstrap | [OFFLINE_SMOKE_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42917820582) | `qsc-acvp-linux-arm64-crypto-offline` |
| 05 | macOS 15 ARM64 · crypto/NEON | Apple Silicon SHA/HMAC, XOF, KDF, AES bootstrap | [OFFLINE_SMOKE_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42932360195) | `qsc-acvp-macos-arm64-crypto-offline` |
| 06 | Linux x64 · scalar | FIPS 203 ML-KEM 512/768/1024 | [OFFLINE_MLKEM_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42933335977) | `qsc-acvp-linux-x64-scalar-mlkem-offline` |
| 07 | Linux x64 · scalar | FIPS 204 ML-DSA 44/65/87 | [OFFLINE_MLDSA_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42936426475) | `qsc-acvp-linux-x64-scalar-mldsa-offline` |
| 08 | Linux x64 · scalar | FIPS 205 SLH-DSA SHAKE 128s/f, 192s/f, 256s/f | [OFFLINE_SLHDSA_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42938226182) | `qsc-acvp-linux-x64-scalar-slhdsa-offline` |
| 09 | Linux x64 · scalar | ECC complete adapter (33 regressions), ten operations | [OFFLINE_ECC_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42939152065) | `qsc-acvp-linux-x64-scalar-ecc-offline` |
| 10 | Linux x64 · AVX2/AES-NI/BMI2 | FIPS 203 ML-KEM 512/768/1024, accelerated backend | [OFFLINE_MLKEM_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42942535115) | `qsc-acvp-linux-x64-avx2-aesni-mlkem-offline` |
| 11 | Linux x64 · AVX2/AES-NI | FIPS 204 ML-DSA and FIPS 205 SLH-DSA, 15 named tests | [OFFLINE_AVX2_SIGNATURES_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42945489346) | `qsc-acvp-linux-x64-avx2-mldsa-slhdsa-offline` |
| 12 | Linux x64 · AVX2/AES-NI | ECC complete adapter (33 regressions), ten operations | [OFFLINE_ECC_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42948565323) | `qsc-acvp-linux-x64-avx2-ecc-offline` |
| 13 | Linux ARM64 · crypto/NEON | FIPS 203/204/205 post-quantum families, 30 checks | [OFFLINE_ARM64_PQ_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42949361481) | `qsc-acvp-linux-arm64-post-quantum-offline` |

**Evidence retention:** the workflow artifacts are configured for 14-day retention. The run links and this report remain available in the repository, but the artifacts must be archived separately before GitHub expires them. This report is an index of evidence, not a substitute for the original logs and manifests.

## Qualification method and coverage

- **Version control and isolation.** Every reviewed stage used the immutable QSC source commit `43c8aa2afe9d38c3ddf9bac0107196545981ac28`, checked out read-only. The test harness, its CMake compilation profiles and workflow corrections reside in `QSC-ACVP`, not the production QSC dependency.
- **Reproducible staging.** The workflows were manually triggered, serialized with the shared `qsc-acvp-sequential-qualification` concurrency group and executed on GitHub-hosted runners. A stage was reviewed before advancing to the next designated stage.
- **Compilation evidence.** The build checked target architecture and QSC compilation-selection macros. Accelerated stages additionally checked exposed CPU capabilities and compiled instruction presence. The Linux AVX2 ML-KEM build additionally required BMI2 and `PEXT` evidence. These inspections do not, on their own, prove dynamic execution of every accelerated branch.
- **Functional evidence.** The bootstraps exercised SHA/HMAC, SP 800-185 XOF, PBKDF/HKDF and AES native qualification adapters. Post-quantum stages exercised the named algorithm parameter sets and supported vector-response, signing/verification, encapsulation/decapsulation and rejection scenarios. ECC stages used an independent `cryptography` oracle across ECDH P-256/P-384/P-521, ECDSA P-256/P-384/P-521, X25519/X448 and Ed25519/Ed448; all 33 ECC adapter regressions passed with zero skips in both designated Linux x64 profiles.
- **Final ARM64 post-quantum stage.** Run 13 completed 12 ML-KEM parser regressions, three native ML-KEM parameter-set tests, three ML-DSA parser regressions, three native ML-DSA tests, three SLH-DSA parser regressions and six native SLH-DSA SHAKE tests (30 checks in the workflow). Native ARM64 NEON arithmetic machine code and required public algorithm symbols were present.

## Failure disposition

An initial execution of the accelerated ML-KEM stage, [Run 42940735875](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42940735875), failed **during compilation**, before its native tests ran. The QSC ML-KEM AVX2 backend used the BMI2 intrinsic `_pext_u32`, but the isolated qualification build had omitted `-mbmi2`. The harness was corrected by scoping BMI2 compilation support to the isolated AVX2 PQ target and requiring CPU and compiled `PEXT` evidence. A fresh execution, [Run 42942535115](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42942535115), then completed the stage successfully. This was a qualification-build configuration issue; the remediation did not modify the pinned QSC source.

Other runs of the same workflow, where present, do not create additional designated campaign stages. Each stage in this register represents one selected, independently verified successful execution.

## Explicit limitations

1. **No NIST server-generated validation.** These tests used local/offline qualification adapters and independent reference comparisons. No authenticated ACVTS submission, validated NIST response set, Demo verdict, CAVP certificate or official laboratory paperwork was produced. Workflow manifests explicitly distinguish these states (for example, `nist_demo: NOT_RUN`).
2. **No exhaustive OS/ISA matrix.** The selected GitHub runners cover targeted high-value configurations, not every supported Windows, Linux and macOS compiler, processor type, scalar fallback or instruction-set branch. AVX-512, unselected OS/ISA combinations and all possible hardware characteristics remain outside the designated campaign.
3. **No dynamic branch-coverage claim.** CPU flags, compiler macro checks, linked backend symbols and disassembled instructions confirm support and inclusion, not coverage of every function or executable branch.
4. **No blanket parameter-set claim.** The campaign uses a class-3 isolated test configuration where specified, plus the explicitly named parameter families. It does not demonstrate every QSC TLS security-class build, every SLH-DSA variant or every cryptographic API offered by QSC.
5. **No security certification claim.** Completion does not attest constant-time behavior, side-channel resistance, formal verification, platform security-module validation or complete cryptographic-module validation.

## Evidence preservation and subsequent validation

Preserve all thirteen GitHub evidence artifacts before their 14-day expiration, together with this report, the immutable source SHA, the qualification workflow SHAs and relevant job logs. Use that frozen snapshot as the starting point for further qualification or reproduction.

Any later change to production QSC source, compilation settings or qualification adapter semantics must be documented and should trigger an appropriately scoped rerun. Formal NIST ACVTS/CAVP validation remains a separate project with its own test-vector process, credentials or accredited validation arrangements as applicable, certificate scope and submitted evidence. The **offline campaign's successful conclusion should not be represented as NIST certification**.

## Qualification workflow revisions

The following qualification repository commits are the revisions executed by the selected successful runs. They differ because the separate, sequential workflows were reviewed and committed as the campaign progressed; the **production QSC SHA remained constant**.

| Stage | GitHub run | Qualification repository revision |
| --- | --- | --- |
| 01 | [42905877018](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42905877018) | `180430463a9cfa99f98fd99739aca7eadac23431` |
| 02 | [42913130713](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42913130713) | `2a41938f4588edc1eca4df5b8046a4505bf7ee1a` |
| 03 | [42914925220](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42914925220) | `3fed407fc73798a515480ac82221c0650fc48f93` |
| 04 | [42917820582](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42917820582) | `dc9594f1180473ae7eda6e72b312e10a3c5e4941` |
| 05 | [42932360195](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42932360195) | `9b30c2c93b8b77981f221fc0f50de7a1d3de93d5` |
| 06 | [42933335977](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42933335977) | `35bd10078856793b7b75bb7fc30a650d3efdb110` |
| 07 | [42936426475](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42936426475) | `c4ad35b78adc688fc1975224c05e3e8295447c14` |
| 08 | [42938226182](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42938226182) | `d9353fde063e27fa27e01878cec75a0b98dd3f51` |
| 09 | [42939152065](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42939152065) | `e65433d51341a84036dc11bb6cef93d8e133aa81` |
| 10 | [42942535115](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42942535115) | `50361ec571f7b72c5256c63f434273d1bcbd788b` |
| 11 | [42945489346](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42945489346) | `cf3fc7236f3e5ce97acb68e703f78062dfcb15b1` |
| 12 | [42948565323](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42948565323) | `2ad70d0019742f7e842eb6075fbb273b3f3f88eb` |
| 13 | [42949361481](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42949361481) | `c4e7f320c6062636031a4194b2f3acac1b7f44e9` |

---

*Report scope: source-pinned, GitHub-hosted offline prequalification evidence only. Verification is limited to the designated test set and reviewed artifacts above.*
