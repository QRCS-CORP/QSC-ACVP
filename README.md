# QSC ACVP Qualification

Independent cryptographic qualification adapters, offline tests, and GitHub-hosted workflows for the [QSC cryptographic library](https://github.com/QRCS-CORP/QSC).

QSC is checked out as an **external read-only dependency**, pinned separately for each run. This repository contains no production QSC cryptographic source files and does not modify the QSC repository.

## ACVTS Demo client — credential-free preparation

The [ACVTS Demo client readiness guide](Source/ACVP/docs/acvts-demo-readiness.md) documents the standards-based NIST Base64/HMAC-SHA256 TOTP implementation, scoped JWT renewal, safe bounded retry and large-response handling, and the protected GitHub environment configuration. Run the [credential-free Demo client protocol regression](.github/workflows/qsc-acvp-demo-readiness.yml) manually before provisioning live credentials. The [authenticated SHA2-256 first-contact workflow](.github/workflows/qsc-acvp-demo.yml) is manual-only, requires an approved `acvts-demo` environment with three NIST credentials and explicit operator authorization, and performs only a sample session. The [credential-free Demo client readiness run](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42960574208) is **verified PASS (25/25 tests)** with `OFFLINE_DEMO_PROTOCOL_PASS` evidence; the authenticated NIST Demo workflow **has not executed** and still requires NIST credentials, a protected environment and explicit approval. Demo access and offline tests are not production CAVP certification.

## Initial offline qualification campaign — completed

The [QSC Offline Qualification Evidence Report](Source/ACVP/docs/offline-qualification-report.md) documents **13 of 13 verified, source-pinned GitHub Actions PASS stages**, including Windows and Linux x64, Linux ARM64 and macOS Apple Silicon, the selected scalar and accelerated compilation profiles, ECC interoperability, and FIPS 203/204/205 algorithm-family prequalification. All thirteen designated runs and their archived evidence artifacts are indexed in the report. This is **offline prequalification only**: no authenticated NIST ACVTS validation, CAVP algorithm certificate, exhaustive instruction-path coverage or FIPS 140-3 validation is claimed. GitHub evidence artifacts are configured for 14-day retention and should be preserved separately for long-term auditability.

## Initial qualification profile

The [Linux x64 scalar offline bootstrap](.github/workflows/qsc-acvp-linux-scalar.yml) is **manually dispatched** on a standard Ubuntu 24.04 GitHub-hosted runner. It accepts an immutable 40-character QSC commit SHA (default `43c8aa2afe9d38c3ddf9bac0107196545981ac28`), checks the scalar compilation macros, builds native SHA/AES adapters, runs offline SHA/HMAC, XOF, KDF and AES tests, and retains sanitized evidence for 14 days.

The [Linux x64 AVX2/AES-NI](.github/workflows/qsc-acvp-linux-avx2.yml), [Windows x64 MSVC AVX2](.github/workflows/qsc-acvp-windows-msvc-avx2.yml), [Linux ARM64 NEON/AES/PMULL](.github/workflows/qsc-acvp-linux-arm64-crypto.yml), and [macOS 15 Apple Silicon ARM64](.github/workflows/qsc-acvp-macos-arm64-crypto.yml) workflows run independently, in that order, after evidence from each preceding profile is reviewed. The ARM64 profile uses a native `ubuntu-24.04-arm` GitHub-hosted runner and `-march=armv8-a+crypto`, checks native CPU capabilities, and inspects compiled ARM instructions. Each workflow requires manual dispatch and records independent results. A successful offline bootstrap is **not** complete QSC qualification, a NIST ACVTS verdict, a Demo validation, a production CAVP certificate, or FIPS 140-3 validation. None of these workflows uses NIST credentials.

## Independent post-quantum algorithm stages

The [Linux x64 scalar ML-KEM FIPS 203 offline qualification](.github/workflows/qsc-acvp-linux-mlkem-scalar.yml) checks all three ML-KEM parameter sets with native adapter and vector-response regression tests. The [Linux x64 scalar ML-DSA FIPS 204 offline qualification](.github/workflows/qsc-acvp-linux-mldsa-scalar.yml) covers ML-DSA-44, ML-DSA-65 and ML-DSA-87 with individually invoked signing/verification and parser tests. The [Linux x64 scalar SLH-DSA FIPS 205 offline qualification](.github/workflows/qsc-acvp-linux-slhdsa-scalar.yml) is a third separate manual stage covering all six SHAKE parameter sets with individual native and parser regression tests. Complete and review one stage before launching the next. Each has its own pinned source revision and fail-closed evidence artifact. These are offline adapter tests, not NIST ACVTS validation.

The [Linux x64 AVX2/AES-NI ML-KEM FIPS 203 qualification](.github/workflows/qsc-acvp-linux-mlkem-avx2.yml) is a separate manual stage. It requires the native AVX2 backend symbols for all three ML-KEM parameter sets, 256-bit vector instruction evidence, and complete native/adapter tests. Compiled instruction presence does not establish dynamic branch coverage.

The [Linux x64 AVX2 ML-DSA and SLH-DSA offline qualification](.github/workflows/qsc-acvp-linux-pq-signatures-avx2.yml) follows the verified AVX2 ML-KEM run. It executes fifteen named, individually checked parser and native tests sequentially in one manually dispatched job with separate CPU, ISA and test evidence. The successful completion of these offline tests does not imply NIST ACVTS validation.

## Independent elliptic-curve qualification

The [Linux x64 scalar complete ECC interoperability workflow](.github/workflows/qsc-acvp-linux-ecc-scalar.yml) is a separately dispatched stage. It requires all 33 native ACVP adapter regressions with no skips, including mandatory ECDSA P-384, and ten independently checked native ECC operations spanning ECDH, ECDSA, X25519/X448 and Ed25519/Ed448. Fail-closed evidence distinguishes offline interoperability from any NIST validation verdict.

The [Linux x64 AVX2 complete ECC interoperability workflow](.github/workflows/qsc-acvp-linux-ecc-avx2.yml) is a separate manual stage requiring all 33 ECC adapter regressions with zero skips, ten independent ECC operations including ECDSA P-384, and CPU/compiled AVX2 instruction evidence. Static AVX2 code inspection does not imply dynamic coverage of every elliptic-curve arithmetic path.

The [Linux ARM64 NEON post-quantum offline qualification](.github/workflows/qsc-acvp-linux-arm64-post-quantum.yml) concludes the proposed initial offline campaign. In one separately dispatched GitHub-hosted ARM64 job, it executes ML-KEM, ML-DSA and SLH-DSA checks sequentially with native vector instruction evidence, strict non-skipping and a separate fail-closed artifact. This does not constitute NIST ACVTS or FIPS validation.

## Repository layout

- `Source/ACVP/` — independent CMake build, bridges, offline adapters and Python tests
- `Source/ACVP/docs/` — qualification runbook and adapter guide
- `.github/workflows/` — individual, manually dispatched OS/ISA qualification workflows
- `dependency/QSC/` — ignored, ephemeral read-only checkout of production QSC

See the [qualification runbook](Source/ACVP/docs/qualification-runbook.md) and [adapter guide](Source/ACVP/docs/adapter-guide.md).

## Local offline bootstrap

```sh
git clone https://github.com/QRCS-CORP/QSC.git dependency/QSC
git -C dependency/QSC checkout 43c8aa2afe9d38c3ddf9bac0107196545981ac28
cmake -G Ninja -S Source/ACVP -B /var/tmp/qsc-acvp-build -DCMAKE_BUILD_TYPE=Release -DQSC_ACVP_ISA_PROFILE=scalar
cmake --build /var/tmp/qsc-acvp-build --target qsc_acvp_hash qsc_acvp_aes --parallel 2
python3 -m unittest discover -s Source/ACVP/tests -p test_demo_client.py -v
```

The explicit scalar profile requires x64 GCC or Clang. Windows MSVC AVX2 and native Linux/macOS ARM64 crypto compile targets are independently selected and require compatible GitHub-hosted runners. Qualification job completion and the original source revision must be recorded for every profile.

## Licensing

Original QRCS copyright and licensing notices are preserved in imported source files. No new product license or additional use rights are implied by this repository; the applicable QRCS licensing terms govern.
