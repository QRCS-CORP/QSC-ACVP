# QSC ACVP Qualification

Independent cryptographic qualification adapters, offline tests, and GitHub-hosted workflows for the [QSC cryptographic library](https://github.com/QRCS-CORP/QSC).

QSC is checked out as an **external read-only dependency**, pinned separately for each run. This repository contains no production QSC cryptographic source files and does not modify the QSC repository.

## Initial qualification profile

The [Linux x64 scalar offline bootstrap](.github/workflows/qsc-acvp-linux-scalar.yml) is **manually dispatched** on a standard Ubuntu 24.04 GitHub-hosted runner. It accepts an immutable 40-character QSC commit SHA (default `43c8aa2afe9d38c3ddf9bac0107196545981ac28`), checks the scalar compilation macros, builds native SHA/AES adapters, runs offline SHA/HMAC, XOF, KDF and AES tests, and retains sanitized evidence for 14 days.

A successful offline bootstrap is **not** a complete library qualification, a NIST ACVTS verdict, a Demo validation, a production CAVP certificate, or FIPS 140-3 validation. No NIST credentials are used.

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

The explicit scalar profile requires x64 GCC or Clang. Future Linux AVX2, Windows and ARM64 workflows will run independently and only after the preceding profile's evidence has been reviewed.

## Licensing

Original QRCS copyright and licensing notices are preserved in imported source files. No new product license or additional use rights are implied by this repository; the applicable QRCS licensing terms govern.
