# QSC ACVP Qualification Runbook

This standalone repository provides GitHub-hosted algorithm prequalification using an **immutable, independently selected QSC source revision**. QSC is a read-only external dependency; no production cryptographic files are copied into this repository.

## Execution policy

Use only standard GitHub-hosted runners. Every operating-system and ISA profile is a separate, manually triggered workflow. All qualification workflows share the `qsc-acvp-sequential-qualification` concurrency group, and results must be reviewed before beginning a new profile. No test is scheduled or executed automatically.

## First profile: Linux x64 scalar offline bootstrap

The workflow `.github/workflows/qsc-acvp-linux-scalar.yml` uses `ubuntu-24.04`, a 20-minute job limit and 14-day artifact retention. It explicitly disables QSC AVX, AES-NI, PCLMUL, SHA-NI and RDRAND code paths in the qualification build (baseline x86-64 SSE2 may remain). It verifies QSC's compilation-selection macros, builds SHA/AES adapters, and executes SHA/HMAC, SP 800-185 XOF, PBKDF/HKDF and AES offline checks.

1. Open **Actions → QSC ACVP Linux x64 scalar offline bootstrap** in `QRCS-CORP/QSC-ACVP`.
2. Select **Run workflow**, choose `main`, and supply the reviewed QSC source commit SHA (default `43c8aa2afe9d38c3ddf9bac0107196545981ac28`).
3. Review the logged QSC revision, qualification revision, compiler configuration and test-stage outcomes.
4. Download `qsc-acvp-linux-x64-scalar-offline` and archive the build configuration and `run-manifest.json`.
5. Resolve any failure or incomplete evidence before running another profile.

The manifest explicitly identifies `nist_demo: NOT_RUN` and `complete_library_qualification: false`. Neither offline PASS nor the GitHub artifact is NIST certification.

## Isolated compilation profiles

`Source/ACVP/CMakeLists.txt` supports:

| ISA profile | Description |
| --- | --- |
| `default` | Compiler default; no claim of ISA coverage |
| `scalar` | GCC/Clang x64 portable crypto paths, with x64 SSE2 baseline permitted |
| `avx2-aesni` | GCC/Clang x64 AVX2 + AES-NI + PCLMUL; Linux workflow checks runtime CPU features and compiled instructions |
| `msvc-avx2` | Native Windows x64 MSVC `/arch:AVX2`, checked against QSC compile-time macros |
| `arm64-crypto` | GCC, Clang, or AppleClang AArch64 `-march=armv8-a+crypto`, with NEON, AES/PMULL and SHA-256 compile-time checks |

Explicit profiles fail CMake configuration if the target compiler/architecture or required QSC compile-time macros do not match. This verifies selected compile-time paths, not dynamic instruction trace coverage.

## Later phases

Following a reviewed Linux scalar PASS, run the separate manually dispatched [Linux AVX2/AES-NI bootstrap](../../../.github/workflows/qsc-acvp-linux-avx2.yml), followed by the independently dispatched [Windows x64 MSVC AVX2 bootstrap](../../../.github/workflows/qsc-acvp-windows-msvc-avx2.yml). The Windows workflow uses `windows-2022`, Visual Studio 2022 and `/arch:AVX2`; it checks CPU features through .NET intrinsics, QSC's preprocessor-selected ISA, and compiled DLL instructions, and records independent evidence. Run it only after the Linux AVX2 profile has been reviewed; do not automatically retry on a failed hosted runner. Following the independently reviewed Windows PASS, dispatch the [Linux ARM64 NEON/AES/PMULL bootstrap](../../../.github/workflows/qsc-acvp-linux-arm64-crypto.yml) on `ubuntu-24.04-arm`. The workflow requires the hosted processor to expose `asimd`, `aes`, `pmull` and `sha2`, and verifies native machine-code presence of `aese`, `pmull`, `sha256h` and NEON vector operations. It is manual-only, creates a separate artifact and fails closed on missing evidence. The Linux AVX2 profile requires the hosted CPU to advertise AVX2, AES, PCLMULQDQ, SSSE3 and SSE4.1; it fails closed if they are absent. Its artifacts include the runner's exposed CPU features and static disassembly evidence for compiled AES-NI, carryless multiplication and 256-bit AVX2 instructions. Static instruction presence does not alone prove dynamic execution of every accelerated function. The SHA/AES interoperability suite remains offline evidence, not NIST validation. Authenticated NIST Demo sessions, certification metadata and formal validation workflow are a separate phase requiring protected secrets and explicit approval. Do not place keys, TOTP seeds, client certificates or session tokens in source or public artifacts.


## Completed offline qualification bootstrap records

| Run | Profile | GitHub Actions result | QSC dependency revision |
| --- | --- | --- | --- |
| 01 | Linux x64 scalar | [OFFLINE_SMOKE_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42905877018) | `43c8aa2afe9d38c3ddf9bac0107196545981ac28` |
| 02 | Linux x64 AVX2/AES-NI | [OFFLINE_SMOKE_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42913130713) | Same pinned revision |
| 03 | Windows x64 MSVC AVX2 | [OFFLINE_SMOKE_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42914925220) | Same pinned revision |
| 04 | Linux ARM64 NEON/AES/PMULL | [OFFLINE_SMOKE_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42917820582) | Same pinned revision |
| 05 | macOS 15 Apple Silicon ARM64 | [OFFLINE_SMOKE_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42932360195) | Same pinned revision |
| 06 | Linux x64 scalar ML-KEM-512/768/1024 | [OFFLINE_MLKEM_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42933335977) | Same pinned revision |
| 07 | Linux x64 scalar ML-DSA-44/65/87 | [OFFLINE_MLDSA_PASS](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42936426475) | Same pinned revision |
| 08 | Linux x64 scalar SLH-DSA SHAKE-128s/f, 192s/f, 256s/f | Not executed | Must use reviewed pinned revision |

These are preliminary offline self-consistency and interoperability checks. They are not ACVTS server-generated verdicts, do not certify QSC, and do not establish complete operating-environment or dynamic branch coverage.


## Next independent profile: macOS ARM64

After reviewing Run 04, manually dispatch the [macOS 15 Apple Silicon ARM64 crypto bootstrap](../../../.github/workflows/qsc-acvp-macos-arm64-crypto.yml) on standard `macos-15` (not the paid `-xlarge` runner). Select the pinned QSC source SHA from previous runs. This profile uses AppleClang and `-march=armv8-a+crypto`, verifies supported Apple Silicon CPU features with `sysctl`, inspects native `.dylib` machine code using `xcrun llvm-objdump`, and performs the same offline SHA/HMAC, XOF, KDF and AES checks. It uses no NIST credentials. Static instruction presence verifies compilation, not dynamic coverage.


## Next algorithm family: ML-KEM (FIPS 203)

After reviewing the five SHA/AES platform bootstraps, manually dispatch [Linux x64 scalar ML-KEM offline qualification](../../../.github/workflows/qsc-acvp-linux-mlkem-scalar.yml). The new workflow uses the same pinned source revision and GCC scalar profile, but builds the standalone post-quantum adapter. It tests ML-KEM-512, ML-KEM-768, and ML-KEM-1024 key generation, deterministic encapsulation, decapsulation, altered ciphertext implicit rejection, ACVP envelope handling, and unsupported-input rejection. It records independent parser-regression and native results and fails closed on incomplete evidence. It is **not** an authenticated NIST ACVTS run, independent algorithm certification, or an exhaustive ML-KEM validation. Run separate ML-DSA and SLH-DSA algorithm stages only after the ML-KEM evidence has been reviewed.


## Next signature family: ML-DSA (FIPS 204)

After reviewing the standalone ML-KEM evidence, manually dispatch [Linux scalar ML-DSA offline qualification](../../../.github/workflows/qsc-acvp-linux-mldsa-scalar.yml). It reuses the pinned, read-only QSC source and the already-defined scalar post-quantum build, while running three individually invoked native signature tests in sequence: ML-DSA-44, ML-DSA-65 and ML-DSA-87. Three separate fail-closed parser regressions cover seeded key generation and unsupported randomized and internal-mu signing modes. Each native test checks signing, signature verification, tampering rejection and supported ACVP-style vector responses. All results are recorded as a distinct sanitized artifact and the run fails on missing, skipped or failed checks. This stage is an offline adapter prequalification only, not a NIST ACVTS verdict or full FIPS 204 validation. SLH-DSA remains a separate future stage.


## Next signature family: SLH-DSA (FIPS 205)

After independently reviewing the ML-DSA results, manually dispatch [Linux x64 scalar SLH-DSA offline qualification](../../../.github/workflows/qsc-acvp-linux-slhdsa-scalar.yml). This is a separate GitHub-hosted workflow on `ubuntu-24.04` using the pinned QSC source and isolated GCC scalar build. Six individually and sequentially invoked native tests exercise the SHAKE-128s, SHAKE-128f, SHAKE-192s, SHAKE-192f, SHAKE-256s and SHAKE-256f parameter sets. Three separately invoked parser regressions verify supported seeded key generation and fail-closed rejection of unsupported nondeterministic signing and prehash modes. Native checks include key generation, deterministic signing, valid signature acceptance, tampered or truncated signature rejection and ACVP-style vector replay. A separate sanitized artifact records named PASS/FAIL evidence and prevents partial runs from being counted as a pass. The job has a 40-minute limit; avoid concurrent qualification workflows. This is offline adapter prequalification, not an authenticated NIST ACVTS verdict or a complete FIPS 205 validation.
