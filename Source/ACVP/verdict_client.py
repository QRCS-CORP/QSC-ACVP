#!/usr/bin/env python3
# 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
# All Rights Reserved.
#  *
# NOTICE:
# This software and all accompanying materials are the exclusive property of
# Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
# and technical concepts contained herein are proprietary to QRCS and are
# protected under applicable Canadian, U.S., and international copyright,
# patent, and trade secret laws.
#  *
# CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
# - This software includes implementations of cryptographic primitives and
#   algorithms that are standardized or in the public domain, such as AES
#   and SHA-3, which are not proprietary to QRCS.
# - This software also includes cryptographic primitives, constructions, and
#   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
#   related components, which are proprietary to QRCS.
# - All source code, implementations, protocol compositions, optimizations,
#   parameter selections, and engineering work contained in this software are
#   original works of QRCS and are protected under this license.
#  *
# LICENSE AND USE RESTRICTIONS:
# - This software is licensed under the Quantum Resistant Cryptographic Solutions
#   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
# - Permission is granted solely for non-commercial evaluation, academic research,
#   cryptographic analysis, interoperability testing, and feasibility assessment.
# - Commercial use, production deployment, commercial redistribution, or
#   integration into products or services is strictly prohibited without a
#   separate written license agreement executed with QRCS.
# - Licensing and authorized distribution are solely at the discretion of QRCS.
#  *
# EXPERIMENTAL CRYPTOGRAPHY NOTICE:
# Portions of this software may include experimental, novel, or evolving
# cryptographic designs. Use of this software is entirely at the user's risk.
#  *
# DISCLAIMER:
# THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
# LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
# ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
#  *
# FULL LICENSE:
# This software is subject to the Quantum Resistant Cryptographic Solutions
# Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
# are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
#  *
# Written by: John G. Underhill
# Contact: contact@qrcscorp.ca
#

"""Read an existing NIST ACVTS Demo session verdict without writing server state.

This client performs one authenticated login and one GET for an existing
test-session result. It never registers sessions, downloads vectors or POSTs
vector-set responses. An expired or inaccessible session requires an explicit
operator decision, not automatic resubmission.
"""

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import sys
import time
import urllib.error

from demo_client import (AcvpUnauthorized, DEMO_API, DemoTransport,
                         reconcile_verdict, totp)


def check_identifier(value: str) -> str:
    """Accept a canonical positive decimal ACVP identifier only."""
    if (not isinstance(value, str) or not value.isascii() or
            not value.isdecimal() or not 1 <= len(value) <= 18 or
            value[0] == "0"):
        raise ValueError("Invalid ACVP session or vector-set identifier")
    return value


def lookup_verdict(transport, seed: str, session_id: str, vector_id: str) -> dict:
    """Perform one read-only status query on an existing test session.

    Args:
        transport: ACVP transport with one-shot request method.
        seed: NIST-provisioned Base64 TOTP seed; never written to reports.
        session_id: Canonical positive decimal identifier from the prior run.
        vector_id: Canonical positive decimal vector-set identifier.
    Returns:
        Sanitized status including the NIST session and vector identifiers.
    Raises:
        ValueError: Invalid input, authorization, or malformed server result.
    """
    session_id = check_identifier(session_id)
    vector_id = check_identifier(vector_id)

    login = transport.request("POST", DEMO_API + "/login", body=[
        {"acvVersion": "1.0"}, {"password": totp(seed, time.time())}])
    if not isinstance(login, list) or len(login) != 2 or not isinstance(login[1], dict):
        raise ValueError("Unexpected NIST login response format")
    token = login[1].get("accessToken")
    if not isinstance(token, str) or not token:
        raise ValueError("NIST login did not return an access token")

    endpoint = DEMO_API + "/testSessions/" + session_id + "/results"
    response = transport.request("GET", endpoint, token)
    if not isinstance(response, list) or len(response) != 2 or not isinstance(response[1], dict):
        raise ValueError("Malformed NIST session verdict response")
    expected = DEMO_API + "/testSessions/" + session_id + "/vectorSets/" + vector_id
    verdict = reconcile_verdict(response[1], {expected})

    allowed = {"passed", "failed", "fail", "error", "expired", "incomplete",
               "missing", "unreceived", "processing", "pending"}
    statuses = sorted({entry["status"] for entry in response[1].get("results", [])
                       if isinstance(entry, dict) and entry.get("status") in allowed})
    outcome = {"PASS": "PASS_DEMO_EXISTING_SAMPLE",
               "PENDING": "PENDING_SERVER",
               "FAIL": "FAIL_DEMO_VERDICT"}[verdict]
    return {
        "type": "NIST_ACVTS_DEMO_EXISTING_SESSION_VERDICT_NOT_CAVP_CERTIFICATE",
        "timestamp_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "mode": "READ_ONLY_NO_TEST_SESSION_REGISTRATION_OR_VECTOR_SUBMISSION",
        "test_session": session_id,
        "vector_set": vector_id,
        "server_passed": verdict == "PASS",
        "vector_verdict_statuses": statuses,
        "status": outcome,
    }


def main() -> int:
    """Query one pre-existing Demo session and persist sanitized evidence."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--session-id", type=str, required=True)
    parser.add_argument("--vector-id", type=str, required=True)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    if args.output.resolve().is_relative_to(root):
        parser.error("Evidence must be written outside the repository")
    session_id = check_identifier(args.session_id)
    vector_id = check_identifier(args.vector_id)
    seed = os.environ.get("ACVP_TOTP_SEED")
    if not seed:
        parser.error("ACVP_TOTP_SEED is required")

    report = {"type": "NIST_ACVTS_DEMO_EXISTING_SESSION_VERDICT_NOT_CAVP_CERTIFICATE",
              "mode": "READ_ONLY_NO_TEST_SESSION_REGISTRATION_OR_VECTOR_SUBMISSION",
              "test_session": session_id, "vector_set": vector_id,
              "server_passed": False, "status": "ERROR_READ_ONLY_VERDICT"}
    try:
        transport = DemoTransport(args.cert, args.key)
        report = lookup_verdict(transport, seed, session_id, vector_id)
    except (ValueError, TypeError, urllib.error.URLError, OSError) as exc:
        report["error_category"] = type(exc).__name__
        if (isinstance(exc, AcvpUnauthorized) or
                (isinstance(exc, ValueError) and "HTTP 403" in str(exc))):
            report["status"] = "SESSION_TOKEN_REQUIRED_OR_ACCESS_RESTRICTED"

    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "existing-session-verdict.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Existing NIST Demo session " + session_id + " verdict status: " +
          report["status"])
    return 0 if report["status"] == "PASS_DEMO_EXISTING_SAMPLE" else 1


if __name__ == "__main__":
    sys.exit(main())
