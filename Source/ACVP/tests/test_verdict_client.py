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

"""Credential-free regression tests for read-only NIST session verdict recovery."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import verdict_client as verdict


class ExistingSessionTransport:
    """Deterministic, in-process mock: one login and one read-only verdict GET."""

    def __init__(self, status="passed", overall=True, token=True):
        self.calls = []
        self.status = status
        self.overall = overall
        self.token = token

    def request(self, method, path, token=None, body=None):
        self.calls.append((method, path, token, body))
        if method == "POST" and path == verdict.DEMO_API + "/login":
            return [{"acvVersion": "1.0"},
                    {"accessToken": "fake-login-token"} if self.token else {}]
        if method == "GET" and path == verdict.DEMO_API + "/testSessions/787623/results":
            return [{"acvVersion": "1.0"},
                    {"passed": self.overall,
                     "results": [{"vectorSetUrl":
                                  verdict.DEMO_API +
                                  "/testSessions/787623/vectorSets/4148699",
                                  "status": self.status}]}]
        raise AssertionError("Unexpected mock ACVTS request")


class ExistingSessionVerdictTests(unittest.TestCase):
    """Individually named read-only verification and negative tests."""

    def test_existing_session_passes_with_exact_vector_match(self):
        server = ExistingSessionTransport()
        report = verdict.lookup_verdict(
            server, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            "787623", "4148699")
        self.assertEqual(report["status"], "PASS_DEMO_EXISTING_SAMPLE")
        self.assertTrue(report["server_passed"])
        self.assertEqual([call[0] for call in server.calls], ["POST", "GET"])
        self.assertEqual(server.calls[1][1],
                         "/acvp/v1/testSessions/787623/results")
        self.assertNotIn("fake-login-token", str(report))
        self.assertNotIn("MTIzNDU2", str(report))

    def test_existing_session_remains_pending_while_processing(self):
        server = ExistingSessionTransport(status="incomplete", overall=False)
        report = verdict.lookup_verdict(
            server, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            "787623", "4148699")
        self.assertEqual(report["status"], "PENDING_SERVER")
        self.assertEqual(report["vector_verdict_statuses"], ["incomplete"])
        self.assertEqual(len(server.calls), 2)

    def test_existing_session_failed_server_verdict_is_not_promoted(self):
        server = ExistingSessionTransport(status="failed", overall=False)
        report = verdict.lookup_verdict(
            server, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            "787623", "4148699")
        self.assertEqual(report["status"], "FAIL_DEMO_VERDICT")
        self.assertFalse(report["server_passed"])

    def test_wrong_vector_id_does_not_promote_successful_session(self):
        server = ExistingSessionTransport()
        report = verdict.lookup_verdict(
            server, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            "787623", "4148700")
        self.assertEqual(report["status"], "FAIL_DEMO_VERDICT")
        self.assertFalse(report["server_passed"])

    def test_invalid_identifier_rejected_before_authentication(self):
        server = ExistingSessionTransport()
        for ident in ("", "0", "0787623", "../787623", "-1", "１２３", "9" * 30):
            with self.subTest(ident=ident), self.assertRaises(ValueError):
                verdict.lookup_verdict(
                    server, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                    ident, "4148699")
        self.assertEqual(server.calls, [])

    def test_missing_login_token_rejected_without_result_query(self):
        server = ExistingSessionTransport(token=False)
        with self.assertRaises(ValueError):
            verdict.lookup_verdict(
                server, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                "787623", "4148699")
        self.assertEqual(len(server.calls), 1)
        self.assertEqual(server.calls[0][1], "/acvp/v1/login")


if __name__ == "__main__":
    unittest.main()
