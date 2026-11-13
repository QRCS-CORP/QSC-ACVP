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

"""Independent HMAC_DRBG-SHA-512 and experimental XDRBG-SHAKE-256 native tests."""

import hashlib
import hmac
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from drbg_client import QscDrbg, build_response, registration


def hmac_update(key, value, supplied):
    key = hmac.new(key, value + b"\x00" + supplied, hashlib.sha512).digest()
    value = hmac.new(key, value, hashlib.sha512).digest()
    if supplied:
        key = hmac.new(key, value + b"\x01" + supplied, hashlib.sha512).digest()
        value = hmac.new(key, value, hashlib.sha512).digest()
    return key, value


class ReferenceHmacDrbg:
    """Independent SP 800-90A HMAC_DRBG-SHA-512 reference state machine."""

    def __init__(self, entropy, nonce, personalization=b""):
        self.key, self.value = hmac_update(b"\x00" * 64, b"\x01" * 64,
                                            entropy + nonce + personalization)

    def reseed(self, entropy, additional=b""):
        self.key, self.value = hmac_update(self.key, self.value, entropy + additional)

    def generate(self, length, additional=b""):
        if additional:
            self.key, self.value = hmac_update(self.key, self.value, additional)
        output = b""
        while len(output) < length:
            self.value = hmac.new(self.key, self.value, hashlib.sha512).digest()
            output += self.value
        self.key, self.value = hmac_update(self.key, self.value, additional)
        return output[:length]


class ReferenceXdrbg:
    """Independent Appendix B XDRBG SHAKE-256 operation encoding."""

    def __init__(self, seed, info=b""):
        self.value = self._operation(seed, info, 0, 64)

    @staticmethod
    def _operation(first, extra, op, length):
        return hashlib.shake_256(first + extra + bytes([85 * op + len(extra)])).digest(length)

    def reseed(self, entropy, additional=b""):
        self.value = self._operation(self.value + entropy, additional, 1, 64)

    def generate(self, length, additional=b""):
        stream = self._operation(self.value, additional, 2, 64 + length)
        self.value = stream[:64]
        return stream[64:]


class DrbgNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.environ.get("QSC_ACVP_DRBG_LIBRARY")
        if not path or not Path(path).is_file():
            raise RuntimeError("QSC_ACVP_DRBG_LIBRARY must point to compiled native backend")
        cls.library = Path(path)

    def test_hcg_instantiate_and_two_generates(self):
        entropy = bytes(range(32))
        nonce = bytes(range(32, 48))
        ref = ReferenceHmacDrbg(entropy, nonce)
        native = QscDrbg(self.library)
        native.instantiate(entropy, nonce)
        try:
            self.assertEqual(native.generate(64), ref.generate(64), "FAIL: HCG first generate")
            self.assertEqual(native.generate(64), ref.generate(64), "FAIL: HCG second generate")
        finally:
            native.dispose()

    def test_hcg_personalization_and_additional_input(self):
        entropy, nonce = bytes(range(32)), bytes(range(32, 48))
        personalization = bytes(range(32, 64))
        additional = bytes(range(40, 72))
        ref = ReferenceHmacDrbg(entropy, nonce, personalization)
        native = QscDrbg(self.library)
        native.instantiate(entropy, nonce, personalization)
        try:
            self.assertEqual(native.generate(80, additional),
                             ref.generate(80, additional), "FAIL: HCG additional input")
            self.assertEqual(native.generate(128),
                             ref.generate(128), "FAIL: HCG post-additional state")
        finally:
            native.dispose()

    def test_hcg_explicit_reseed(self):
        entropy, nonce = bytes(range(32)), bytes(range(32, 48))
        reseed, extra = bytes(range(64, 96)), bytes(range(32))
        ref = ReferenceHmacDrbg(entropy, nonce)
        native = QscDrbg(self.library)
        native.instantiate(entropy, nonce)
        try:
            native.generate(32)
            ref.generate(32)
            native.reseed(reseed, extra)
            ref.reseed(reseed, extra)
            self.assertEqual(native.generate(64), ref.generate(64),
                             "FAIL: HCG explicit reseed")
        finally:
            native.dispose()

    def test_hcg_rejects_invalid_entropy_and_disposed_state(self):
        native = QscDrbg(self.library)
        with self.assertRaisesRegex(ValueError, "instantiate"):
            native.instantiate(bytes(15), bytes(16))
        with self.assertRaisesRegex(ValueError, "generate"):
            native.generate(64)
        native.instantiate(bytes(range(32)), bytes(range(32, 48)))
        native.dispose()
        with self.assertRaisesRegex(ValueError, "generate"):
            native.generate(64)

    def test_hcg_acvp_registration_dependencies(self):
        item = registration()
        self.assertEqual(item["algorithm"], "hmacDRBG")
        self.assertEqual(item["revision"], "SP800-90Ar1")
        self.assertEqual(item["prereqVals"], [{"algorithm": "HMAC", "valValue": "same"}])
        self.assertEqual(item["predResistanceEnabled"], [False])

    def test_hcg_acvp_two_generate_response(self):
        entropy, nonce = bytes(range(32)), bytes(range(32, 48))
        ref = ReferenceHmacDrbg(entropy, nonce)
        ref.generate(64)
        expected = ref.generate(64).hex().upper()
        sample = [{"acvVersion": "1.0"}, {"algorithm": "hmacDRBG",
                  "revision": "SP800-90Ar1", "vsId": 17,
                  "testGroups": [{"tgId": 8, "testType": "AFT",
                  "mode": "SHA2-512", "predResistance": False, "reSeed": False,
                  "entropyInputLen": 256, "nonceLen": 128,
                  "persoStringLen": 0, "additionalInputLen": 0,
                  "returnedBitsLen": 512,
                  "tests": [{"tcId": 13, "entropyInput": entropy.hex(),
                  "nonce": nonce.hex(), "persoString": "",
                  "otherInput": [{"intendedUse": "generate", "additionalInput": ""},
                                 {"intendedUse": "generate", "additionalInput": ""}]}]}]}]
        native = QscDrbg(self.library)
        response = build_response(sample, native)
        self.assertEqual(response[1]["testGroups"][0]["tests"][0]["returnedBits"],
                         expected, "FAIL: HCG ACVP returnedBits should be second generate")

    def test_csg_candidate_generate_and_reseed(self):
        seed, additional = bytes(range(48)), bytes(range(30))
        ref = ReferenceXdrbg(seed, additional)
        native = QscDrbg(self.library, "csg")
        native.instantiate(seed, personalization=additional)
        try:
            self.assertEqual(native.generate(128), ref.generate(128),
                             "FAIL: CSG candidate first generate")
            native.reseed(bytes(range(32)), additional)
            ref.reseed(bytes(range(32)), additional)
            self.assertEqual(native.generate(200, additional), ref.generate(200, additional),
                             "FAIL: CSG candidate post-reseed generate")
        finally:
            native.dispose()

    def test_csg_candidate_rejects_legacy_short_seed(self):
        native = QscDrbg(self.library, "csg")
        with self.assertRaisesRegex(ValueError, "instantiate"):
            native.instantiate(bytes(32))
        with self.assertRaisesRegex(ValueError, "nonce"):
            native.instantiate(bytes(48), nonce=bytes(16))

    def test_hcg_output_request_bounds(self):
        native = QscDrbg(self.library)
        native.instantiate(bytes(32), bytes(16))
        try:
            with self.assertRaisesRegex(ValueError, "generate"):
                native.generate(65537)
            self.assertEqual(len(native.generate(65536)), 65536)
        finally:
            native.dispose()


    def test_hcg_acvp_explicit_reseed_vector(self):
        entropy = bytes(range(32))
        nonce = bytes(range(32, 48))
        personalization = bytes(range(48, 80))
        fresh = bytes(range(80, 112))
        reseed_additional = bytes(range(112, 144))
        generate_first = bytes(range(144, 176))
        generate_second = bytes(range(176, 208))
        ref = ReferenceHmacDrbg(entropy, nonce, personalization)
        ref.reseed(fresh, reseed_additional)
        ref.generate(64, generate_first)
        expected = ref.generate(64, generate_second)
        sample = [{"acvVersion": "1.0"}, {"algorithm": "hmacDRBG",
                  "revision": "SP800-90Ar1", "vsId": 31,
                  "testGroups": [{"tgId": 7, "testType": "AFT", "mode": "SHA2-512",
                  "predResistance": False, "reSeed": True, "entropyInputLen": 256,
                  "nonceLen": 128, "persoStringLen": 256,
                  "additionalInputLen": 256, "returnedBitsLen": 512,
                  "tests": [{"tcId": 17, "entropyInput": entropy.hex(),
                  "nonce": nonce.hex(), "persoString": personalization.hex(),
                  "otherInput": [
                      {"intendedUse": "reSeed", "additionalInput": reseed_additional.hex(),
                       "entropyInput": fresh.hex()},
                      {"intendedUse": "generate", "additionalInput": generate_first.hex(),
                       "entropyInput": ""},
                      {"intendedUse": "generate", "additionalInput": generate_second.hex(),
                       "entropyInput": ""}
                  ]}]}]}]
        native = QscDrbg(self.library)
        actual = build_response(sample, native)[1]["testGroups"][0]["tests"][0]["returnedBits"]
        self.assertEqual(actual, expected.hex().upper(),
                         "FAIL: HCG ACVP explicit reseed/second generate mismatch")

    def test_hcg_combined_seed_without_separate_nonce(self):
        combined = bytes(range(48))
        ref = ReferenceHmacDrbg(combined, b"")
        native = QscDrbg(self.library)
        native.instantiate(combined)
        try:
            self.assertEqual(native.generate(96), ref.generate(96),
                             "FAIL: HCG combined-entropy instantiate")
        finally:
            native.dispose()

    def test_hcg_unaligned_generate_lengths(self):
        entropy, nonce = bytes(range(32)), bytes(range(32, 48))
        ref = ReferenceHmacDrbg(entropy, nonce)
        native = QscDrbg(self.library)
        native.instantiate(entropy, nonce)
        try:
            for n in (1, 63, 65, 129, 344, 513):
                self.assertEqual(native.generate(n), ref.generate(n),
                                 f"FAIL: HCG unaligned request length {n}")
        finally:
            native.dispose()

    def test_hcg_acvp_rejects_malformed_reseed_vector(self):
        entropy, nonce = bytes(range(32)), bytes(range(32, 48))
        group = {"tgId": 1, "testType": "AFT", "mode": "SHA2-512",
                 "predResistance": False, "reSeed": True,
                 "entropyInputLen": 256, "nonceLen": 128,
                 "persoStringLen": 0, "additionalInputLen": 0,
                 "returnedBitsLen": 512, "tests": [
                     {"tcId": 11, "entropyInput": entropy.hex(), "nonce": nonce.hex(),
                      "persoString": "", "otherInput": [
                          {"intendedUse": "generate", "additionalInput": "",
                           "entropyInput": ""},
                          {"intendedUse": "generate", "additionalInput": "",
                           "entropyInput": ""}]}]}
        sample = [{"acvVersion": "1.0"}, {"algorithm": "hmacDRBG",
                  "revision": "SP800-90Ar1", "vsId": 51, "testGroups": [group]}]
        native = QscDrbg(self.library)
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            build_response(sample, native)

    def test_csg_candidate_multigenerate(self):
        seed = bytes(range(48))
        ref = ReferenceXdrbg(seed)
        native = QscDrbg(self.library, "csg")
        native.instantiate(seed)
        try:
            for n in (1, 64, 65, 344):
                self.assertEqual(native.generate(n), ref.generate(n),
                                 f"FAIL: CSG XDRBG output length {n}")
        finally:
            native.dispose()

    def test_csg_candidate_request_bounds(self):
        native = QscDrbg(self.library, "csg")
        with self.assertRaisesRegex(ValueError, "generate"):
            native.generate(1)
        native.instantiate(bytes(range(48)))
        try:
            with self.assertRaisesRegex(ValueError, "generate"):
                native.generate(345)
            with self.assertRaisesRegex(ValueError, "generate"):
                native.generate(0)
        finally:
            native.dispose()

    def test_hcg_acvp_prerequisites_enforced(self):
        from demo_client import registration as demo_registration
        with self.assertRaisesRegex(ValueError, "SHA2-512"):
            demo_registration(("hmacDRBG",))
        with self.assertRaisesRegex(ValueError, "SHA2-512"):
            demo_registration(("HMAC-SHA2-512", "hmacDRBG"))
        self.assertEqual([c["algorithm"] for c in
                         demo_registration(("SHA2-512", "HMAC-SHA2-512", "hmacDRBG"))[1]["algorithms"]],
                         ["SHA2-512", "HMAC-SHA2-512", "hmacDRBG"],
                         "FAIL: hmacDRBG same-session SHA/HMAC registration")



if __name__ == "__main__":
    unittest.main()
