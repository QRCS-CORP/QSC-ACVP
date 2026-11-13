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

"""Read-only diagnostic of existing ACVTS KDA-HKDF vector-set structures.

The output contains only field names, structural error codes, and counts.
The client never creates a test session or submits a vector-set response.
"""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import sys
import time

from demo_client import (DEMO_API, DemoTransport, RefreshingTransport, totp,
                         check_path)
from kda_hkdf_client import KdaHexError, _hex


def _inspect_field(counts, label, value, bound):
    """Classify one fixed KDA hex input without retaining its contents."""
    try:
        _hex(value, bound, label)
    except KdaHexError as exc:
        counts["HEX_" + exc.field + "_" + exc.issue] += 1


def inspect_vector(envelope):
    """Return only bounded, non-sensitive structural diagnostics for one vector."""
    if (not isinstance(envelope, list) or len(envelope) != 2 or
            not isinstance(envelope[1], dict)):
        raise ValueError("Invalid KDA vector envelope")
    body = envelope[1]
    if (body.get("algorithm") != "KDA" or body.get("mode") != "HKDF" or
            type(body.get("vsId")) is not int or
            not isinstance(body.get("testGroups"), list) or
            len(body["testGroups"]) > 256):
        raise ValueError("Unexpected KDA vector type")
    counts = Counter()
    groups = 0
    cases = 0
    for group in body["testGroups"]:
        groups += 1
        if not isinstance(group, dict) or not isinstance(group.get("tests"), list):
            counts["MALFORMED_GROUP"] += 1
            continue
        if len(group["tests"]) > 10000:
            counts["OVERSIZED_TEST_GROUP"] += 1
            continue
        test_type = group.get("testType")
        for case in group["tests"]:
            cases += 1
            if not isinstance(case, dict):
                counts["MALFORMED_CASE"] += 1
                continue
            parameters = case.get("kdfParameter")
            if not isinstance(parameters, dict):
                counts["MISSING_KDF_PARAMETER"] += 1
                continue
            _inspect_field(counts, "Z", parameters.get("z"), 8192)
            _inspect_field(counts, "SALT", parameters.get("salt"), 8192)
            for prefix, key in (("U", "fixedInfoPartyU"), ("V", "fixedInfoPartyV")):
                party = case.get(key)
                if not isinstance(party, dict):
                    counts["MISSING_" + prefix + "_PARTY"] += 1
                    continue
                _inspect_field(counts, prefix + "_PARTY_ID", party.get("partyId"), 512)
                if "ephemeralData" in party:
                    _inspect_field(counts, prefix + "_EPHEMERAL",
                                   party["ephemeralData"], 1024)
            if test_type == "VAL":
                _inspect_field(counts, "DKM", case.get("dkm"), 256)
    return {
        "vector_set": body["vsId"],
        "revision": body.get("revision") if body.get("revision") in
                    ("Sp800-56Cr1", "Sp800-56Cr2") else "UNKNOWN",
        "groups_checked": groups,
        "cases_checked": cases,
        "issues": dict(sorted(counts.items())),
    }


def inspect_session(transport, seed, session_id, vector_ids):
    """Fetch only existing KDA vectors using authenticated GET operations."""
    if (type(session_id) is not int or session_id <= 0 or
            not isinstance(vector_ids, tuple) or len(vector_ids) != 2 or
            any(type(x) is not int or x <= 0 for x in vector_ids)):
        raise ValueError("Invalid preexisting ACVP session/vector identifiers")
    transport = RefreshingTransport(transport, seed)
    login = transport.request("POST", DEMO_API + "/login", body=[
        {"acvVersion": "1.0"}, {"password": totp(seed, time.time())}])
    token = login[1].get("accessToken")
    if not isinstance(token, str) or not token:
        raise ValueError("Missing ACVP login token")
    base = DEMO_API + "/testSessions/" + str(session_id)
    session = transport.request("GET", base, token)[1]
    session_token = session.get("accessToken", token)
    if not isinstance(session_token, str) or not session_token:
        raise ValueError("Invalid ACVP session token")
    results = []
    for vector_id in vector_ids:
        path = check_path(base + "/vectorSets/" + str(vector_id))
        envelope = transport.request("GET", path, session_token)
        if envelope[1].get("vsId") != vector_id:
            raise ValueError("Vector-set ID mismatch")
        results.append(inspect_vector(envelope))
    return {"status": "READ_ONLY_SCHEMA_INSPECTED", "session": session_id,
            "vectors": results, "response_submissions": 0}


def main():
    """Inspect one existing session and persist sanitized results only."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cert", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--session-id", required=True, type=int)
    parser.add_argument("--vector-ids", required=True, nargs=2, type=int)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = {"status": "READ_ONLY_ACCESS_FAILED", "session": args.session_id,
              "response_submissions": 0}
    status = 1
    try:
        seed = os.environ["ACVP_TOTP_SEED"]
        transport = DemoTransport(args.cert, args.key)
        report = inspect_session(transport, seed, args.session_id, tuple(args.vector_ids))
        status = 0
    except (ValueError, TypeError, OSError, KeyError) as exc:
        report["error_category"] = type(exc).__name__
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("ACVP KDA read-only session inspection: " + report["status"])
    return status


if __name__ == "__main__":
    sys.exit(main())
