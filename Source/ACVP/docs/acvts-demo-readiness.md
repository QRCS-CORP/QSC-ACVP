# QSC ACVTS Demo Client Readiness

## Scope and control

This document describes the credential-free integration state of the QSC ACVTS
Demo client. It governs the qualification repository
[`QRCS-CORP/QSC-ACVP`](https://github.com/QRCS-CORP/QSC-ACVP).
The production QSC source remains pinned to
[`43c8aa2afe9d38c3ddf9bac0107196545981ac28`](https://github.com/QRCS-CORP/QSC/commit/43c8aa2afe9d38c3ddf9bac0107196545981ac28).
The completed 13-stage offline qualification evidence is retained separately in
[offline-qualification-report.md](offline-qualification-report.md). None of the
credential-free preparation stages constitute a NIST Demo or production verdict.

## Deployment workflows

| Workflow | Credential requirement | Scope | Dispatch policy |
| --- | --- | --- | --- |
| [Demo protocol readiness](../../../.github/workflows/qsc-acvp-demo-readiness.yml) | None | Mock-server SHA sample, credential/TOTP validation, transport rejection/renewal tests | Manual only |
| [Authenticated Demo first contact](../../../.github/workflows/qsc-acvp-demo.yml) | NIST mTLS certificate, matching private key and Base64 TOTP seed | Single SHA2-256 `isSample: true` session with actual server verdict | Manual only; approved `acvts-demo` environment and explicit run approval |

**The authenticated workflow is deliberately disabled until credentials and
GitHub environment protection have been set up by an authorized maintainer.**
Neither workflow is scheduled or triggered by pushes. The first-contact
workflow does not include ECC, KDA-HKDF, post-quantum algorithms or a non-sample
registration; these require individual subsequent qualification decisions.

## Credentials and GitHub configuration

An authorized maintainer must perform all of the following before initiating
the first live NIST Demo request:

1. Obtain a client mTLS certificate from NIST and retain its matching private
   key under organizational key-management controls. NIST's key-issuance
   instructions determine how the CSR is generated and accepted. The private
   key must never be committed, included in issue comments, shared in chat,
   uploaded to repository artifacts or reproduced in a report.
2. Obtain the TOTP seed associated with the same authenticated identity.
   NIST specifies Base64 encoding, HMAC-SHA256, eight decimal digits, a
   30-second interval and a zero Unix-time offset. Synchronize the runtime
   clock before attempting login.
3. Create a repository **GitHub Environment** named `acvts-demo`. Enable
   required-reviewer approval and restrict deployment to the reviewed
   `main` branch. Configure the environment variable
   `ACVTS_DEMO_ENABLED` with the literal value `true`. Without this
   variable or explicit dispatch approval, the live workflow fails closed.
4. Add the following **environment secrets**, not repository files or
   workflow-dispatch inputs:

   | GitHub environment secret | Format |
   | --- | --- |
   | `ACVTS_DEMO_CERT_B64` | Standard Base64 encoding of the complete NIST-issued client certificate PEM file |
   | `ACVTS_DEMO_KEY_B64` | Standard Base64 encoding of its matching private-key PEM file |
   | `ACVTS_DEMO_TOTP_B64` | The NIST-provisioned Base64 TOTP key, copied unchanged |

5. Review permissions and branch restrictions, confirm that GitHub Actions
   artifact access is appropriately restricted, and explicitly dispatch the
   first-contact workflow from `main` with
   `approve_nist_network_session=true`.

The job checks that the certificate and key are parsable and belong to the
same public key before contacting NIST. Private-key and certificate files are
written only to the ephemeral runner's temporary directory with restrictive
permissions and are removed in an unconditional cleanup step. Only sanitized
`demo-results.json` is eligible for upload. GitHub's environment and secret
administration are external actions that cannot be completed by committing
repository files.

## Credential-free protocol behavior

### Authentication and authorization

- TOTP derives from the NIST-provided Base64 key with RFC 6238 HMAC-SHA256,
  eight digits and 30-second time steps. RFC 6238 deterministic SHA-256
  test vectors and malformed-secret cases are part of the regression suite.
- The client authenticates over mutual TLS with certificate verification,
  refuses redirects and restricts ordinary API resources to the NIST Demo
  origin.
- On an explicit HTTP 401, a scoped JWT may be refreshed once by requesting
  `POST /acvp/v1/login` with a fresh TOTP and the old access token, then
  retrying the refused operation. The renewal does not expose JWTs or TOTP
  values in sanitized reports.
- Only idempotent GET requests have bounded retries for HTTP 429, 502, 503
  and 504. POST response submissions are not retried after ambiguous network
  failures. Server-reported vector-generation `retry` intervals are bounded.

### Result size and authorization

- Normal submissions have the transport's bounded JSON size limit.
- When NIST requires a large submission, the client requests a server grant
  from `POST /acvp/v1/large`, submits a bounded one-time response with the
  granted access token, and does not automatically repeat the upload.
- Delegated uploads are restricted to the official NIST Demo HTTPS origin or
  an operator-specified, explicitly approved `--large-origin`. No NIST
  delegate origin is presumed in advance. The first-contact workflow does
  not authorize third-party upload origins.
- Duplicate vector sets, mismatched vector-set IDs, unsupported vector
  modes, incomplete algorithm coverage and incomplete or inconsistent
  NIST verdicts cannot be reported as passing.

## Verification gates and unexecuted checks

The test suite is
`python -m unittest discover -s Source/ACVP/tests -p test_demo_client.py -v`.
It includes deterministic TOTP test vectors, invalid credentials, 401 refresh,
missing JWT renewal, GET retry bounds, non-replay of POSTs, large-submission
grant handling, rejected cross-origin uploads, unsupported vectors, duplicate
vector sets, coverage checks and negative server verdicts.

**These new regressions are committed, but are not recorded as passed until
the credential-free GitHub readiness workflow has actually executed.**
A workflow-definition review is not equivalent to a successful build or test.
Only the manually dispatched, successful GitHub run and its manifest can
advance the readiness test gate.

## Post-credential sequence

1. Complete and independently review the credential-free workflow.
2. Configure the protected environment after NIST credentials arrive and
   confirm NIST's instructions still match the current public authentication
   specification.
3. Dispatch one authenticated SHA2-256 sample and verify the actual NIST
   session and vector-set `passed` verdicts. Preserve only sanitized
   results, run link, source revision and operating-environment information.
4. Review each additional capability against the server's accepted ACVP
   algorithm schemas and locally implemented vector modes **before**
   enabling it in a separate manual workflow. Run families independently,
   with verified prerequisites and no unsupported capabilities advertised.
5. Handle non-sample registration, vendor/module/operational-environment
   metadata, applicable DRBG validation prerequisites, session recovery
   policy and certification submission according to NIST's then-current
   procedures. These have **not** been completed or exercised in the
   SHA2-256 first-contact workflow.
6. For production CAVP algorithm certificates, coordinate with an
   appropriately accredited validation laboratory. NIST Demo credentials
   alone are not production validation authorization.

## Normative sources

- [NIST ACVP credential and TOTP requirements](https://github.com/usnistgov/ACVP/wiki/Credentials-Specification-for-Accessing-ACVP)
- [ACVP protocol, login renewal, sessions and large submission](https://pages.nist.gov/ACVP/draft-fussell-acvp-spec.html)
- [NIST ACVP repository and documentation](https://github.com/usnistgov/ACVP)

## Qualification status

- Original offline campaign: **13 designated stages verified PASS**.
- Credential-free Demo-client regression workflow: **committed; execution pending**.
- Authenticated NIST Demo sample: **not executed; NIST credentials required**.
- NIST production algorithm certification: **not executed**.
