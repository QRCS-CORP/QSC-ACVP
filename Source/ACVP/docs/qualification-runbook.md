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
| `avx2-aesni` | GCC/Clang x64 AVX2 + AES-NI + PCLMUL; future workflow requires runtime CPU feature verification |

Explicit profiles fail CMake configuration if the target compiler/architecture or required QSC compile-time macros do not match. This verifies selected compile-time paths, not dynamic instruction trace coverage.

## Later phases

Following a reviewed Linux scalar PASS, add separate Linux AVX2, Windows AVX2 and selected ARM64 qualification workflows. Authenticated NIST Demo sessions, certification metadata and formal validation workflow are a separate phase requiring protected secrets and explicit approval. Do not place keys, TOTP seeds, client certificates or session tokens in source or public artifacts.
