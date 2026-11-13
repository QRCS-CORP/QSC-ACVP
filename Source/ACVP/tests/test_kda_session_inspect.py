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

"""Offline tests for bounded read-only KDA ACVP session diagnostics."""

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from kda_session_inspect import inspect_session, inspect_vector
from test_kda_hkdf_vectors import vectors


class KdaSessionInspectTests(unittest.TestCase):
    def test_read_only_valid_kda_vector_has_no_hex_issues(self):
        request = vectors()
        result = inspect_vector(request)
        self.assertEqual(result["cases_checked"], 1)
        self.assertEqual(result["issues"], {})
        self.assertEqual(result["revision"], "Sp800-56Cr1")

    def test_read_only_scans_all_malformed_kda_fields(self):
        request = vectors("Sp800-56Cr2", "VAL")
        case = request[1]["testGroups"][0]["tests"][0]
        del case["kdfParameter"]["z"]
        case["kdfParameter"]["salt"] = "GG"
        case["fixedInfoPartyU"]["partyId"] = 23
        case["fixedInfoPartyV"]["ephemeralData"] = "A"
        del case["dkm"]
        result = inspect_vector(request)
        self.assertEqual(result["issues"], {
            "HEX_DKM_MISSING": 1,
            "HEX_SALT_ENCODING": 1,
            "HEX_U_PARTY_ID_TYPE": 1,
            "HEX_V_EPHEMERAL_ODD_LENGTH": 1,
            "HEX_Z_MISSING": 1
        })
        self.assertNotIn("GG", str(result))

    def test_read_only_never_exposes_vector_byte_strings(self):
        request = vectors()
        case = request[1]["testGroups"][0]["tests"][0]
        case["kdfParameter"]["salt"] = "SENSITIVE_PRIVATE_STRING"
        result = inspect_vector(request)
        self.assertEqual(result["issues"], {"HEX_SALT_ENCODING": 1})
        self.assertNotIn("SENSITIVE_PRIVATE_STRING", str(result))
        self.assertNotIn(str(case["kdfParameter"]["z"]), str(result))

    def test_default_salt_and_null_optional_ephemeral_are_not_invalid_hex(self):
        """Read-only diagnostics recognize valid optional HKDF input forms."""
        for revision in ("Sp800-56Cr1", "Sp800-56Cr2"):
            with self.subTest(revision=revision):
                request = vectors(revision=revision)
                group = request[1]["testGroups"][0]
                group["kdfConfiguration"]["saltMethod"] = "default"
                case = group["tests"][0]
                case["kdfParameter"]["salt"] = None
                case["fixedInfoPartyU"]["ephemeralData"] = None
                case["fixedInfoPartyV"]["ephemeralData"] = None
                self.assertEqual(inspect_vector(request)["issues"], {})

    def test_read_only_session_uses_no_registration_or_result_posts(self):
        class ReadOnlyMock:
            def __init__(self):
                self.calls = []

            def request(self, method, path, token=None, body=None):
                self.calls.append((method, path))
                if path.endswith("/login"):
                    return [{"acvVersion": "1.0"}, {"accessToken": "mock-login"}]
                if path.endswith("/testSessions/787983"):
                    return [{"acvVersion": "1.0"}, {"accessToken": "mock-session"}]
                if path.endswith("/vectorSets/4151665"):
                    reply = vectors()
                    reply[1]["vsId"] = 4151665
                    return reply
                if path.endswith("/vectorSets/4151666"):
                    reply = vectors("Sp800-56Cr2", "VAL")
                    reply[1]["vsId"] = 4151666
                    return reply
                raise AssertionError("Unexpected ACVP request")

        server = ReadOnlyMock()
        answer = inspect_session(server,
                                 "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                                 787983, (4151665, 4151666))
        self.assertEqual(answer["status"], "READ_ONLY_SCHEMA_INSPECTED")
        self.assertEqual(answer["response_submissions"], 0)
        self.assertEqual(len(answer["vectors"]), 2)
        self.assertEqual([method for method, _ in server.calls],
                         ["POST", "GET", "GET", "GET"])
        self.assertEqual(server.calls[0][1], "/acvp/v1/login")
        self.assertTrue(all("/results" not in path for _, path in server.calls))
        self.assertTrue(all("/testSessions" not in path or method == "GET"
                            for method, path in server.calls))


if __name__ == "__main__":
    unittest.main()
