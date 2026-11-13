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


## Stage 2 implementation design: SP 800-90A HMAC_DRBG

### Target mechanism

Implement a **separate**, opt-in HMAC_DRBG provider conforming to NIST SP 800-90A Revision 1, Section 10.1.2, initially using QSC's existing HMAC-SHA-512 primitive. This is **not** a rename, alias, or change of the existing HCG or CSG algorithms. The mechanism is not production-validated until the applicable testing and certificate prerequisites are independently met.

The compact provider is intended to support a 256-bit security-strength profile. Initially scope its ACVP registration to `hmacDRBG`, `SP800-90Ar1`, `SHA2-512`, `predResistanceEnabled: [false]`, and `reseedImplemented: true`. The permitted entropy, nonce, personalization, additional-input, and returned-bit lengths must be validated against the actual selected ACVP protocol revision and capability constraints. Do not advertise prediction resistance or any additional SHA mode until it is implemented and tested.

### Required state and operations

Maintain the HMAC_DRBG Key and V state (64 bytes each for SHA-512), a reseed counter, and a defined initialization state. Implement the standard's instantiate, Update, reseed, generate, and uninstantiate operations, including:

- The two-step HMAC_DRBG_Update construction with control bytes 0x00 and 0x01, using the second branch only when provided_data is nonempty.
- Instantiate from externally supplied entropy, nonce, and optional personalization data. The caller must prove the input's entropy provenance and strength; raw buffer length is not sufficient.
- Generate with optional additional input, bounded request size, counter checks, state update after output, and fail-closed reseed requirements.
- Reseed with fresh qualified entropy and optional additional input, resetting the reseed counter correctly. Do not silently substitute custom HCG/CSG output.
- Uninstantiate by securely erasing state and invalidating the instance; enforce ownership and thread-safety rules in the API documentation.

Use established QSC HMAC-SHA-512, `qsc_memutils_*`, and `qsc_intutils_*` functions; verify their signatures in the local dependency headers before implementation. Avoid C runtime memory-copy or compare functions where a suitable QSC utility exists. Preserve the exact authorized license for any new source/header, Allman braces, tab indentation, single exit, and complete QSC-style Doxygen documentation.

### Integration: prerequisite must be real

The current ECC ACVP adapter obtains some key-generation seeds/scalars directly through `os.urandom` or `secrets.randbelow`. Its current DRBG validation reference is registration metadata, not proof of an integrated generator. **Do not unlock live ECC qualification solely because a plausible DRBG validation identifier is supplied.**

Before claiming that the DRBG meets an ECC prerequisite, route the ECC adapter's random requirements through the actual approved provider: unbiased P-256/P-384/P-521 private-scalar generation with valid range and rejection sampling, Ed25519/Ed448 seed generation, X25519/X448 ephemeral private generation, and any seeded-keypair operations. Verify exact input ownership, lifecycle, cleanup, and failure propagation. Coordinate whether production QSC APIs or an authorized, separate provider interface must be changed; do not modify protected QSC dependencies without explicit approval.

The KDA-HKDF adapter must likewise be reconciled with its declared `DRBG` prerequisite, particularly its registration of random-salt capabilities. Passing a test whose salt is provided in the ACVP vector is not by itself evidence of an integrated approved random generator.

### Qualification gates

1. Independent deterministic KAT/reference tests, first for SHA-512 HMAC_DRBG instantiate/update/generate, then reseed and additional-input cases. Include empty optional fields, sequential calls, boundaries, forced reseed, uninstantiate, and negative/error tests.
2. Exact ACVP `otherInput` parsing: `reSeed` and `generate` sequences, bit-length checks, no accidental string/byte conversion, and `returnedBits` from the specified generation call. Test before contacting NIST.
3. Separately verified entropy-source assumption and correct binding of each consuming ECC operation to the selected provider; no automatic operating-system RNG fallback in the qualification path.
4. A manually dispatched, source-pinned and credential-protected single DRBG Demo session, with HMAC/SHA prerequisites in the same session if required. Confirm actual server verdict; a Demo pass is not a production algorithm certificate.
5. Only after the appropriate approved prerequisite mechanism and validation provenance have been established, resume the six blocked ECC/KDA selections one family at a time, with complete mode coverage and independent offline tests.

NIST references: SP 800-90A Rev. 1 (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf) and the ACVP DRBG JSON specification (https://pages.nist.gov/ACVP/draft-vassilev-acvp-drbg.html). The latter is a 2026 Internet-Draft; verify the revision the NIST Demo service actually supports before registration.

**Authorization boundary:** This plan changes the QSC-ACVP qualification documents only. It does not authorize edits to the protected production QSC repository, does not claim a DRBG implementation exists, and does not create a usable validation number.
