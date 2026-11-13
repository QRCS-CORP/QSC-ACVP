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

"""Native QSC HCG-driven HKDF regression tests against independent RFC 5869 oracle."""

import os
from pathlib import Path
import sys
import unittest

TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))
from drbg_client import QscDrbg
from kdf_client import QscKdf
from kda_hkdf_client import response
from test_kda_hkdf_vectors import oracle, vectors


class KdaHcgNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        drbg_path = os.environ.get("QSC_ACVP_DRBG_LIBRARY")
        hash_path = os.environ.get("QSC_ACVP_HASH_LIBRARY")
        if not drbg_path or not Path(drbg_path).is_file():
            raise RuntimeError("QSC_ACVP_DRBG_LIBRARY is required")
        if not hash_path or not Path(hash_path).is_file():
            raise RuntimeError("QSC_ACVP_HASH_LIBRARY is required")
        cls.drbg_path = Path(drbg_path)
        cls.kdf = QscKdf(Path(hash_path))

    def test_hcg_native_salt_and_sha512_hkdf(self):
        native = QscDrbg(self.drbg_path)
        native.instantiate(bytes(range(32)), bytes(range(32, 48)))
        try:
            salt = native.generate(32)
            secret = bytes(range(28))
            info = bytes(range(40, 60))
            actual = self.kdf.hkdf("SHA2-512", secret, salt, info, 64)
            expected = oracle("SHA2-512", secret, salt, info, 64)
            self.assertEqual(actual, expected,
                             "FAIL: HCG-supplied salt and native QSC HKDF-SHA512")
        finally:
            native.dispose()

    def test_kda_native_hkdf_aft_all_registered_sha2(self):
        for digest in ("SHA2-256", "SHA2-384", "SHA2-512"):
            request = vectors(digest=digest)
            answer = response(request, self.kdf)
            expected = response(request, type("Reference", (), {
                "hkdf": staticmethod(oracle)})())
            self.assertEqual(answer, expected,
                             f"FAIL: native KDA-HKDF AFT {digest}")

    def test_kda_native_large_party_fixed_info_both_revisions(self):
        """Verify native SHA2 HKDF with both parties exceeding the old 1 KiB cap."""
        reference = type("Reference", (), {"hkdf": staticmethod(oracle)})()
        for revision in ("Sp800-56Cr1", "Sp800-56Cr2"):
            for digest in ("SHA2-256", "SHA2-384", "SHA2-512"):
                with self.subTest(revision=revision, digest=digest):
                    request = vectors(revision=revision, digest=digest)
                    case = request[1]["testGroups"][0]["tests"][0]
                    case["fixedInfoPartyU"]["ephemeralData"] = "AB" * 4096
                    case["fixedInfoPartyV"]["ephemeralData"] = "CD" * 4096
                    actual = response(request, self.kdf)
                    expected = response(request, reference)
                    self.assertEqual(actual, expected,
                                     f"FAIL: native large FixedInfo {revision} {digest}")

    def test_kda_native_fixed_info_maximum_both_parties(self):
        """Verify the entire registered 64 KiB per-party diagnostic bound."""
        request = vectors(revision="Sp800-56Cr2", digest="SHA2-512")
        case = request[1]["testGroups"][0]["tests"][0]
        case["fixedInfoPartyU"]["ephemeralData"] = "21" * 65536
        case["fixedInfoPartyV"]["ephemeralData"] = "43" * 65536
        actual = response(request, self.kdf)
        expected = response(request, type("Reference", (), {
            "hkdf": staticmethod(oracle)})())
        self.assertEqual(actual, expected,
                         "FAIL: native HKDF with 128 KiB combined ephemeral FixedInfo")

    def test_kda_native_hkdf_val_all_registered_sha2(self):
        for digest in ("SHA2-256", "SHA2-384", "SHA2-512"):
            request = vectors(revision="Sp800-56Cr2", test_type="VAL", digest=digest)
            answer = response(request, self.kdf)
            self.assertTrue(answer[1]["testGroups"][0]["tests"][0]["testPassed"],
                            f"FAIL: native KDA-HKDF VAL {digest}")


if __name__ == "__main__":
    unittest.main()
