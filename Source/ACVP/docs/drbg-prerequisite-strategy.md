# DRBG prerequisites for remaining ACVP algorithm selections

## Scope and qualification status

The authenticated ACVTS Demo campaign has passed the non-ECC algorithm selections through SLH-DSA. Six configured selections remain: ECDSA, DetECDSA, EDDSA, XECDH, KAS-ECC-SSC, and KDA-HKDF. This document addresses the prerequisite and evidence constraints for these selections; it does not establish algorithm validation, ACVP production approval, FIPS 140-3 certification, or approved random-number generation.

The production QSC dependency inspected for this audit is pinned at commit `43c8aa2afe9d38c3ddf9bac0107196545981ac28`. No production QSC files are modified by this stage.

## Findings

- QSC HCG is a customized HMAC-SHA-512-based generator with its own nonce, info and internal update behavior. Its source-level design is not asserted to be the standardized SP 800-90A HMAC_DRBG mechanism.
- QSC CSG is a customized cSHAKE-based generator. SP 800-90A Rev. 1 does not define a cSHAKE DRBG construction matching CSG. Merely passing local statistical, vector or generator tests is insufficient to claim an ACVP DRBG validation.
- The current ECC and KDA-HKDF registration adapters accept a supplied nonempty DRBG validation reference; they cannot authenticate that reference against a certificate or prove that the intended module actually uses the claimed validated generator. A syntactically accepted reference is **not evidence of validation**.
- HCG, CSG, aliases for those custom generators, and missing or placeholder DRBG references are explicitly rejected by the ECC and KDA registration adapters. Synthetic references in offline mock tests must never be supplied to a real NIST session.
- Existing ECC scalar/AVX2 and HKDF tests establish *offline adapter and interoperability evidence*, not the missing prerequisite. Verification-only operations should not be exempted from the ACVP registration's declared prerequisite without a documented NIST-compliant alternative.

## Recommended qualification path

1. Select a standards-defined SP 800-90A DRBG mechanism, such as HMAC_DRBG with SHA-256 or SHA-512, and implement it as a separately scoped, optional provider if absent. Do not relabel HCG or CSG as HMAC_DRBG.
2. Independently verify supported instantiate, reseed, generate, prediction-resistance, personalization, additional-input and error paths against the appropriate ACVP vector format. Verify entropy and reseed assumptions separately. Use QSC-first memory and integer helpers and retain the repository-authorized license and coding standard.
3. Obtain authentic ACVP/ACVTS evidence for the actual DRBG implementation and its module, with provenance recorded. Confirm with the program/laboratory how the prerequisite certificate or same-session registration is to be referenced.
4. Audit each of the six remaining algorithm registrations for the relevant DRBG and dependent SHA/HMAC prerequisites, parameter-set limits, mode coverage and vector response formatting. Keep one manually authorized NIST Demo session per algorithm family.
5. Run existing ECC scalar and AVX2 offline qualification and independent HKDF regression again after any required native changes. Do not change production QSC or protected dependencies without approval.

## Current controls

A manually dispatched, credential-free audit workflow at `.github/workflows/qsc-acvp-demo-drbg-prerequisite-audit.yml` runs 17 ECC schema tests and 11 KDA-HKDF schema tests, checks missing and invalid DRBG references, and makes no NIST request. Its results constitute offline prerequisite-integrity checks only.

No NIST DRBG validation, usable DRBG certificate number, or complete end-to-end prerequisite evidence has been established in this stage. The remaining live ECC/KDA sessions are intentionally blocked pending that evidence.
