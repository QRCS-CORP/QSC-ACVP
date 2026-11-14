# QSC NIST ACVTS Demo evidence | November 2026

**25 independently planned sample qualification targets passed; 86 submitted vector sets; two source-pinned QSC cohorts.**

The complete [public qualification report](qualification-report.md) and [machine-readable evidence manifest](evidence-manifest.json) are the authoritative records of the campaign. The [CSV register](evidence-index.csv) includes each target, NIST Demo session, GitHub Actions run, exact source pin, vector-set IDs and original-artifact SHA-256 digest.

The original sanitized artifacts from all 25 GitHub Actions runs have been downloaded and preserved by QRCS as a separate controlled archive. GitHub Actions' own copies are ephemeral. The public manifest refers to those archives by verified hash; the original ZIP files are not committed into Git source control here. The full ZIP and editable PDF/DOCX were saved to the organization's archive for publication through the appropriate release mechanism.

**Evidence boundaries:** These were `isSample:true` NIST ACVTS Demo sessions and are not CAVP algorithm certificates or FIPS 140-3 module validations. The first SHA2-256 sample contains an inconsistent intermediate `incomplete` status despite an overall successful server verdict; later SHA2-256 sessions contain independent `passed` verdicts. Source revisions differ across two cohorts, as recorded in the manifest.

For audit, begin with `qualification-report.md`, locate the session in `evidence-manifest.json`, verify `original_artifact_sha256` against the preserved original ZIP and then follow its `github_url` to the GitHub Actions record if retained.

**Public claim:** "25 of 25 planned NIST ACVTS Demo sample qualification targets passed (November 2026)." Do not use a NIST/FIPS certification logo for this campaign.
