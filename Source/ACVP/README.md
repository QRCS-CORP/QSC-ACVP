# QSC ACVP Qualification

Standalone algorithm qualification adapters and regression tests for [QSC](https://github.com/QRCS-CORP/QSC), maintained in the separate [QSC-ACVP](https://github.com/QRCS-CORP/QSC-ACVP) repository.

QSC production source is a read-only, external checkout under `dependency/QSC`; qualification workflows record its immutable commit independently.

## Local offline bootstrap

```sh
git clone https://github.com/QRCS-CORP/QSC.git dependency/QSC
git -C dependency/QSC checkout 43c8aa2afe9d38c3ddf9bac0107196545981ac28
cmake -G Ninja -S Source/ACVP -B /var/tmp/qsc-acvp-build -DCMAKE_BUILD_TYPE=Release -DQSC_ACVP_ISA_PROFILE=scalar
cmake --build /var/tmp/qsc-acvp-build --target qsc_acvp_hash qsc_acvp_aes --parallel 2
python3 -m unittest discover -s Source/ACVP/tests -p test_demo_client.py -v
```

Use `-DQSC_ROOT=/path/to/QSC/Source` when QSC is checked out elsewhere. Full legacy CAVP and ECC qualification requires the complete P-384 implementation; missing components do not qualify. Offline test verdicts are not NIST ACVTS server verdicts or certificates. See [qualification runbook](docs/qualification-runbook.md) and [adapter guide](docs/adapter-guide.md).
