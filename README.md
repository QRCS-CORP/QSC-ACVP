# QSC ACVP Qualification

Independent cryptographic qualification adapters, offline tests, and GitHub-hosted workflows for the [QSC cryptographic library](https://github.com/QRCS-CORP/QSC).

QSC is checked out as an **external read-only dependency**, pinned separately for each run. This repository contains no production QSC cryptographic source files and does not modify the QSC repository.

## Initial qualification profile

The [Linux x64 scalar offline bootstrap](.github/workflows/qsc-acvp-linux-scalar.yml) is **manually dispatched** on a standard Ubuntu 24.04 GitHub-hosted runner. It accepts an immutable 40-character QSC commit SHA (default `43c8aa2afe9d38c3ddf9bac0107196545981ac28`), checks the scalar compilation macros, builds native SHA/AES adapters, runs offline SHA/HMAC, XOF, KDF and AES tests, and retains sanitized evidence for 14 days.

The [Linux x64 AVX2/AES-NI](.github/workflows/qsc-acvp-linux-avx2.yml), [Windows x64 MSVC AVX2](.github/workflows/qsc-acvp-windows-msvc-avx2.yml), [Linux ARM64 NEON/AES/PMULL](.github/workflows/qsc-acvp-linux-arm64-crypto.yml), and [macOS 15 Apple Silicon ARM64](.github/workflows/qsc-acvp-macos-arm64-crypto.yml) workflows run independently, in that order, after evidence from each preceding profile is reviewed. The ARM64 profile uses a native `ubuntu-24.04-arm` GitHub-hosted runner and `-march=armv8-a+crypto`, checks native CPU capabilities, and inspects compiled ARM instructions. Each workflow requires manual dispatch and records independent results. A successful offline bootstrap is **not** complete QSC qualification, a NIST ACVTS verdict, a Demo validation, a production CAVP certificate, or FIPS 140-3 validation. None of these workflows uses NIST credentials.

## Independent post-quantum algorithm stages

The [Linux x64 scalar ML-KEM FIPS 203 offline qualification](.github/workflows/qsc-acvp-linux-mlkem-scalar.yml) checks all three ML-KEM parameter sets with native adapter and vector-response regression tests. The [Linux x64 scalar ML-DSA FIPS 204 offline qualification](.github/workflows/qsc-acvp-linux-mldsa-scalar.yml) covers ML-DSA-44, ML-DSA-65 and ML-DSA-87 with individually invoked signing/verification and parser tests. The [Linux x64 scalar SLH-DSA FIPS 205 offline qualification](.github/workflows/qsc-acvp-linux-slhdsa-scalar.yml) is a third separate manual stage covering all six SHAKE parameter sets with individual native and parser regression tests. Complete and review one stage before launching the next. Each has its own pinned source revision and fail-closed evidence artifact. These are offline adapter tests, not NIST ACVTS validation.

The [Linux x64 AVX2/AES-NI ML-KEM FIPS 203 qualification](.github/workflows/qsc-acvp-linux-mlkem-avx2.yml) is a separate manual stage. It requires the native AVX2 backend symbols for all three ML-KEM parameter sets, 256-bit vector instruction evidence, and complete native/adapter tests. Compiled instruction presence does not establish dynamic branch coverage.

## Independent elliptic-curve qualification

The [Linux x64 scalar complete ECC interoperability workflow](.github/workflows/qsc-acvp-linux-ecc-scalar.yml) is a separately dispatched stage. It requires all 33 native ACVP adapter regressions with no skips, including mandatory ECDSA P-384, and ten independently checked native ECC operations spanning ECDH, ECDSA, X25519/X448 and Ed25519/Ed448. Fail-closed evidence distinguishes offline interoperability from any NIST validation verdict.

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
