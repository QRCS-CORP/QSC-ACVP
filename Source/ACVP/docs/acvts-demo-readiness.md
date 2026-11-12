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

## Verified credential-free regression evidence

The test suite is
`python -m unittest discover -s Source/ACVP/tests -p test_demo_client.py -v`.
It includes deterministic TOTP test vectors, invalid credentials, 401 refresh,
missing JWT renewal, GET retry bounds, non-replay of POSTs, large-submission
grant handling, rejected cross-origin uploads, unsupported vectors, duplicate
vector sets, coverage checks and negative server verdicts.

The credential-free readiness workflow completed with
**`OFFLINE_DEMO_PROTOCOL_PASS`** in
[GitHub Actions Run 42960574208](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/42960574208).
The runner successfully performed Python compilation checks and executed
**25 named mock-server and protocol regression tests with no failures or skips**.
It verified that NIST credentials were not required and uploaded the
`qsc-acvp-demo-protocol-readiness-offline` evidence artifact (GitHub artifact
ID `13828738336`). The artifact was downloaded, its ZIP CRC verified, and its
`run-manifest.json` independently inspected. The manifest records the reviewed
qualification commit `30af6129bc13cdab8634c8b5013a2924ca9247fe`,
`nist_demo: NOT_CONTACTED`, `credentials: NOT_USED`, and
`status: OFFLINE_DEMO_PROTOCOL_PASS`.

This is a **verified offline protocol-readiness result**, not a NIST server
verdict. It was completed before the first authenticated NIST Demo session.

## First authenticated NIST Demo contact — November 12, 2026

The initial [authenticated SHA2-256 sample run](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43319257508)
used the pinned QSC source revision
`43c8aa2afe9d38c3ddf9bac0107196545981ac28` and qualification revision
`f9ceb82f0a5459e6e3cf3248355fb88285aa8ee8`. The certificate/private-key
pair passed validation, NIST Demo authentication succeeded, and the server
registered **sample test session 787623**, vector set **4148699** for
**SHA2-256**. The client submitted the generated response successfully.
Its final report was `INCOMPLETE` because the eight short, two-second
verdict polls concluded before NIST returned a conclusive disposition.

The original sanitized evidence artifact is
`qsc-acvp-real-nist-demo-sha2-256-sample`, artifact ID `13990066496`.
The client did not receive a passing or failing NIST test verdict. No
certificate or formal algorithm validation is claimed.

NIST documentation explains that a received vector set may remain
`incomplete` during server processing, sometimes for several minutes.
The default verdict polling has been changed to **20 checks at 30-second
intervals**, preserving a sanitized `PENDING_SERVER` state if the bounded
window expires. This change applies to future sessions; it was **not**
tested during Run 43319257508.

A separate, manually dispatched
[read-only recovery workflow](../../../.github/workflows/qsc-acvp-demo-verdict-only.yml)
can check the **existing** session and vector-set status. It performs one
fresh login and one GET
`/acvp/v1/testSessions/787623/results`, and does **not** create or modify
test sessions or upload responses. The accompanying
`test_verdict_client.py` mock tests must pass in the credential-free
workflow before the recovery workflow is used.

**Authorization limitation:** the original session-scoped JWT was not
retained. NIST may reject a fresh login JWT for access to the earlier
session. Such a result is recorded as
`SESSION_TOKEN_REQUIRED_OR_ACCESS_RESTRICTED`; it is not interpreted as
an algorithm failure. If that happens, stop and review the server's
session-token recovery procedures rather than repeatedly resubmitting data.

## Confirmed first authenticated Demo PASS — November 12, 2026

The subsequent [NIST Demo SHA2-256 sample run 43321340135](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43321340135)
completed successfully using qualification revision
`7a19748e3965eec747aff1913ce756fbd6db00c6` and the unchanged
production QSC revision
`43c8aa2afe9d38c3ddf9bac0107196545981ac28`.

The actual NIST Demo response for **sample session 787624**, vector set
**4148700**, was reconciled against the submitted vector set and reported
`PASS_DEMO_SAMPLE` with `server_passed: true`. The live GitHub job's
authenticated execution step returned success, and the sanitized
`demo-results.json` was downloaded from evidence artifact **13990472131**.
The artifact passed ZIP CRC verification; its SHA-256 archive digest is
`0c2e37845184d13a1a52d40a865e6d866f723419595ff6b54bdbc0cece70c6e5`.

The archived JSON has a benign evidence-field inconsistency:
`vector_verdict_statuses: ["incomplete"]` reflects an earlier polling
response, although the final reconciled response passed. This is not a
failed NIST vector verdict. The reporting client has since been adjusted
to capture statuses from the **last** poll and a deterministic regression
has been added. The complete updated **32-test credential-free suite
passed** in [run 43327458656](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43327458656)
(26 Demo-client and six recovery tests). The original run's evidence
is retained unchanged for provenance.

The earlier sample session **787623** remains without a recorded final
verdict; its status must not be inferred from the independent PASS for
787624. Neither Demo sample implies a CAVP algorithm certificate or
FIPS 140-3 validation.

## Second confirmed authenticated Demo PASS — SHA2-384

The [NIST Demo SHA2-384 sample run 43328100214](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43328100214)
executed the isolated SHA2-384 sample with qualification revision
`feb320f936aa84aa4359b9c938efefa401d781f5`, using the unchanged
production QSC revision `43c8aa2afe9d38c3ddf9bac0107196545981ac28`.

The pinned QSC SHA2-384 known-answer preflight passed, a single
authenticated NIST Demo session **787625** was created, and vector set
**4148701** was submitted. NIST's verdict was
`PASS_DEMO_SAMPLE` with `server_passed: true`; the final
`vector_verdict_statuses` was `["passed"]` after three verdict polls.
The sanitized evidence archive is artifact **13992789114**, with SHA-256:
`46445e6e78204e48404edf5ec94e02680c8ecc2fb2e1f9c28ad7124df8c07c5c`.
The ZIP CRC was verified.

The subsequent [SHA2-512 sample workflow](../../../.github/workflows/qsc-acvp-demo-sha2-512.yml)
is prepared with the same protected environment, pinned dependency and
exclusive NIST session concurrency group. It has **not been executed**.
NIST Demo success is distinct from formal CAVP algorithm validation.

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
- Credential-free Demo-client regression workflow: **[32/32 PASS, verified](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43327458656)** (26 Demo-client and six recovery tests); evidence manifest `OFFLINE_DEMO_PROTOCOL_PASS`.
- Authenticated NIST Demo SHA2-256: **[Run 43321340135 — PASS_DEMO_SAMPLE](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43321340135)** for session 787624, vector 4148700, with actual NIST server verdict; previous session 787623 remains **unconfirmed**.
- Authenticated NIST Demo SHA2-384: **[Run 43328100214 — PASS_DEMO_SAMPLE](https://github.com/QRCS-CORP/QSC-ACVP/actions/runs/43328100214)** for session 787625, vector 4148701; sanitized evidence verified.
- Authenticated NIST Demo SHA2-512: **workflow prepared; not executed**.
- NIST production algorithm certification: **not executed**.
