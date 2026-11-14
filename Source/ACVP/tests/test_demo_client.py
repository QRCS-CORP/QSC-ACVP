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

"""Tests for Demo protocol orchestration and strict credential handling."""

import importlib.util
from pathlib import Path
import sys
import unittest

TOOL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL_ROOT))
import demo_client as client


class FakeTransport:
    """Deterministic test-only server, returning ACVP-shaped responses."""

    def __init__(self, test_type="AFT", passes=True):
        self.test_type = test_type
        self.passes = passes
        self.calls = []
        self.session = client.DEMO_API + "/testSessions/42"
        self.vector = self.session + "/vectorSets/91"

    def request(self, method, path, token=None, body=None):
        self.calls.append((method, path, token, body))
        if path == client.DEMO_API + "/login":
            return [{"acvVersion": "1.0"}, {"accessToken": "private-login-token"}]
        if method == "POST" and path == client.DEMO_API + "/testSessions":
            return [{"acvVersion": "1.0"}, {"url": self.session, "accessToken": "private-session-token",
                      "vectorSetUrls": [self.vector]}]
        if method == "GET" and path == self.vector:
            return [{"acvVersion": "1.0"}, {"vsId": 91, "algorithm": "SHA2-256", "revision": "1.0",
                    "testGroups": [{"tgId": 4, "testType": self.test_type,
                                    "tests": [{"tcId": 9, "msg": "616263", "len": 24}]}]}]
        if method == "POST" and path == self.vector + "/results":
            return [{"acvVersion": "1.0"}, {"status": "received"}]
        if method == "GET" and path == self.session + "/results":
            return [{"acvVersion": "1.0"}, {"passed": self.passes,
                    "results": [{"vectorSetUrl": self.vector,
                                 "status": "passed" if self.passes else "failed"}]}]
        raise AssertionError(f"Unexpected request {method} {path}")


class Oracle:
    def digest(self, algorithm, message, output_bits, key=b""):
        return "AB" * (output_bits // 8)


class DemoClientTests(unittest.TestCase):
    def test_acvts_totp_rfc6238_sha256_base64_eight_digit_vectors(self):
        """Verify independent published RFC 6238 SHA-256 8-digit vectors."""
        seed = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
        self.assertEqual(client.totp(seed, 59), "46119246")
        self.assertEqual(client.totp(seed, 1111111109), "68084774")
        self.assertEqual(client.totp(seed, 1111111111), "67062674")
        self.assertEqual(client.totp(seed, 1234567890), "91819424")
        self.assertEqual(client.totp(seed, 2000000000), "90698825")
        self.assertEqual(client.totp(seed, 20000000000), "77737706")

    def test_acvts_totp_preserves_leading_zeroes_and_base64_whitespace(self):
        seed = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
        padded = seed[:12] + " \n " + seed[12:]
        self.assertEqual(client.totp(padded, 2000000000), "90698825")
        self.assertEqual(client.totp(seed, 90), "02975832")
        self.assertEqual(len(client.totp(seed, 90)), 8)

    def test_acvts_totp_rejects_malformed_secret_and_timestamp(self):
        seed = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
        for bad in ("", "not@base64", "AQID", "AAAA==%"):
            with self.subTest(seed=bad), self.assertRaises(ValueError):
                client.totp(bad, 59)
        for timestamp in (-1, float("nan"), float("inf"), 2 ** 64):
            with self.subTest(timestamp=timestamp), self.assertRaises(ValueError):
                client.totp(seed, timestamp)

    def test_rejected_registration_reports_http_status_without_server_text(self):
        """Registration HTTP failures yield a fixed stage and bounded status code."""
        class Rejected(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "POST" and path == client.DEMO_API + "/testSessions":
                    raise ValueError("ACVP request rejected with HTTP 400")
                return super().request(method, path, token, body)

        server = Rejected()
        selected = ("SHA2-512", "SHAKE-256", "HMAC-SHA2-512",
                    "hmacDRBG", "EDDSA")
        with self.assertRaises(client.AcvpPreSessionError) as caught:
            client.execute(server, Oracle(),
                           "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                           selected, poll_count=1, drbg_validation="same")
        self.assertEqual(caught.exception.stage, "REGISTER_SESSION",
                         "FAIL: rejected EDDSA registration stage")
        self.assertEqual(caught.exception.diagnostic_code, "HTTP_400",
                         "FAIL: sanitized NIST registration HTTP code")
        self.assertNotIn("private-login-token", str(caught.exception),
                         "FAIL: NIST login token entered diagnostics")
        self.assertFalse(any(method == "GET" and "/vectorSets" in path
                             for method, path, _, _ in server.calls),
                         "FAIL: vector fetch started before registration")

    def test_registration_missing_session_url_is_diagnostic_not_raw_text(self):
        """Unexpected registration response must not be logged verbatim."""
        class InvalidRegistration(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "POST" and path == client.DEMO_API + "/testSessions":
                    return [{"acvVersion": "1.0"},
                            {"accessToken": "private-session-token",
                             "unexpectedSecret": "sensitive-server-error-text"}]
                return super().request(method, path, token, body)

        with self.assertRaises(client.AcvpPreSessionError) as caught:
            client.execute(InvalidRegistration(), Oracle(),
                           "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                           ("SHA2-256",), poll_count=1)
        self.assertEqual((caught.exception.stage, caught.exception.diagnostic_code),
                         ("PARSE_REGISTRATION", "INVALID_SESSION_URL"),
                         "FAIL: rejected registration response not categorized")
        self.assertNotIn("sensitive-server-error-text", str(caught.exception),
                         "FAIL: raw registration response leaked")

    def test_login_failure_and_unclassified_errors_are_redacted(self):
        """Login cannot leak raw server messages; no session registration follows."""
        class RejectLogin(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "POST" and path == client.DEMO_API + "/login":
                    raise client.AcvpUnauthorized("sensitive-login-error-text")
                return super().request(method, path, token, body)

        server = RejectLogin()
        with self.assertRaises(client.AcvpPreSessionError) as caught:
            client.execute(server, Oracle(),
                           "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                           ("SHA2-256",), poll_count=1)
        self.assertEqual((caught.exception.stage, caught.exception.diagnostic_code),
                         ("LOGIN", "HTTP_401"),
                         "FAIL: sanitized login rejection stage")
        self.assertNotIn("sensitive-login-error-text", str(caught.exception),
                         "FAIL: login error response leaked")
        self.assertEqual(
            client._pre_session_diagnostic(ValueError("private-server-response")),
            "UNCLASSIFIED_VALUE_ERROR",
            "FAIL: unknown server error should remain opaque")

    def test_expired_session_token_refreshes_once_and_preserves_claims(self):
        """Only an explicit 401 permits one scoped TOTP login and replay."""
        class ExpiringTransport(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector and token == "private-session-token":
                    self.calls.append((method, path, token, body))
                    raise client.AcvpUnauthorized("ACVP bearer token expired")
                if method == "POST" and path == client.DEMO_API + "/login" and body[1].get("accessToken"):
                    self.calls.append((method, path, token, body))
                    self.renewal = body
                    return [{"acvVersion": "1.0"}, {"accessToken": "private-refreshed-token"}]
                return super().request(method, path, token, body)

        server = ExpiringTransport()
        seed = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
        report = client.execute(server, Oracle(), seed, ("SHA2-256",), poll_count=1)
        self.assertEqual(report["status"], "PASS_DEMO_SAMPLE")
        self.assertEqual(server.renewal[1]["accessToken"], "private-session-token")
        self.assertEqual(len(server.renewal[1]["password"]), 8)
        self.assertTrue(any(method == "POST" and path == server.vector + "/results"
                            and token == "private-refreshed-token"
                            for method, path, token, body in server.calls))
        self.assertNotIn("private-session-token", str(report))
        self.assertNotIn("private-refreshed-token", str(report))

    def test_refresh_missing_token_does_not_retry_or_pass(self):
        """An unsuccessful refresh never produces a positive session result."""
        class MissingRefresh(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    raise client.AcvpUnauthorized("expired")
                if method == "POST" and path == client.DEMO_API + "/login" and body[1].get("accessToken"):
                    return [{"acvVersion": "1.0"}, {}]
                return super().request(method, path, token, body)

        server = MissingRefresh()
        report = client.execute(server, Oracle(),
                                "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                                ("SHA2-256",), poll_count=1)
        self.assertEqual(report["status"], "FAIL_OR_UNSUPPORTED_VECTOR")
        self.assertFalse(report["server_passed"])

    def test_non401_network_error_does_not_retry_ambiguous_submission(self):
        """Network errors are fail-closed rather than causing duplicate POSTs."""
        class BrokenSubmit(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "POST" and path == self.vector + "/results":
                    self.calls.append((method, path, token, body))
                    raise OSError("test-only network failure")
                return super().request(method, path, token, body)

        server = BrokenSubmit()
        report = client.execute(server, Oracle(),
                                "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                                ("SHA2-256",), poll_count=1)
        self.assertEqual(report["status"], "FAIL_OR_UNSUPPORTED_VECTOR")
        self.assertEqual(sum(1 for method, path, token, body in server.calls
                             if method == "POST" and path == server.vector + "/results"), 1)

    def test_aes_ecb_rejected_group_records_sanitized_stage_and_code(self):
        """A rejected AES vector exposes only reviewed diagnostics, never secrets."""
        class BadAesGroup(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    self.calls.append((method, path, token, body))
                    return [{"acvVersion": "1.0"},
                            {"vsId": 91, "algorithm": client.AES_ECB, "revision": "1.0",
                             "testGroups": [{"tgId": 7, "testType": "AFT",
                                             "direction": "encrypt", "keyLen": 192,
                                             "tests": [{"tcId": 8, "key": "00" * 24,
                                                        "pt": "00" * 16}]}]}]
                return super().request(method, path, token, body)

        server = BadAesGroup()
        cipher = Oracle()
        cipher.aes = object()
        report = client.execute(
            server, cipher, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            (client.AES_ECB,), poll_count=1)
        self.assertEqual(report["status"], "FAIL_OR_UNSUPPORTED_VECTOR")
        result = report["vectors"][0]
        self.assertEqual(result["reason"], "ValueError")
        self.assertEqual(result["stage"], "BUILD_RESPONSE")
        self.assertEqual(result["diagnostic_code"], "UNSUPPORTED_GROUP")
        self.assertNotIn("private-login-token", str(report))
        self.assertNotIn("private-session-token", str(report))
        self.assertFalse(any(method == "POST" and path == server.vector + "/results"
                             for method, path, token, body in server.calls))

    def test_aes_ecb_unrecognized_error_never_leaks_exception_text(self):
        """Unrecognized native adapter failures receive a fixed opaque error code."""
        class ValidAesGroup(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    return [{"acvVersion": "1.0"},
                            {"vsId": 91, "algorithm": client.AES_ECB, "revision": "1.0",
                             "testGroups": [{"tgId": 7, "testType": "AFT",
                                             "direction": "encrypt", "keyLen": 128,
                                             "tests": [{"tcId": 8, "key": "00" * 16,
                                                        "pt": "00" * 16}]}]}]
                return super().request(method, path, token, body)

        class RejectingAes:
            def ecb(self, key, block, encryption):
                raise ValueError("sensitive-adapter-internal-text")

        server = ValidAesGroup()
        cipher = Oracle()
        cipher.aes = RejectingAes()
        report = client.execute(
            server, cipher, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            (client.AES_ECB,), poll_count=1)
        result = report["vectors"][0]
        self.assertEqual(result["stage"], "BUILD_RESPONSE")
        self.assertEqual(result["diagnostic_code"], "UNCLASSIFIED_VALUE_ERROR")
        self.assertNotIn("sensitive-adapter-internal-text", str(report))
        self.assertNotIn("private-session-token", str(report))

    def test_aes_ctr_rejected_vector_records_allowlisted_error(self):
        """Bad CTR payload metadata yields a stage and safe diagnostic code."""
        class BadCtrVector(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    return [{"acvVersion": "1.0"},
                            {"vsId": 91, "algorithm": client.AES_CTR, "revision": "1.0",
                             "testGroups": [{"tgId": 7, "testType": "AFT",
                                             "direction": "encrypt", "keyLen": 128,
                                             "tests": [{"tcId": 8, "key": "00" * 16,
                                                        "iv": "00" * 16, "pt": "00" * 16,
                                                        "payloadLen": 64}]}]}]
                return super().request(method, path, token, body)

        server = BadCtrVector()
        cipher = Oracle()
        cipher.aes = object()
        report = client.execute(
            server, cipher, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            (client.AES_CTR,), poll_count=1)
        self.assertEqual(report["status"], "FAIL_OR_UNSUPPORTED_VECTOR")
        result = report["vectors"][0]
        self.assertEqual(result["stage"], "BUILD_RESPONSE")
        self.assertEqual(result["reason"], "ValueError")
        self.assertEqual(result["diagnostic_code"], "PAYLOAD_LEN")
        self.assertNotIn("private-login-token", str(report))
        self.assertNotIn("private-session-token", str(report))
        self.assertFalse(any(method == "POST" and path == server.vector + "/results"
                             for method, path, token, body in server.calls))

    def test_aes_ctr_unknown_exception_text_is_not_reported(self):
        """Opaque native CTR errors must not expose implementation details."""
        class ValidCtrVector(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    return [{"acvVersion": "1.0"},
                            {"vsId": 91, "algorithm": client.AES_CTR, "revision": "1.0",
                             "testGroups": [{"tgId": 7, "testType": "AFT",
                                             "direction": "encrypt", "keyLen": 128,
                                             "tests": [{"tcId": 8, "key": "00" * 16,
                                                        "iv": "00" * 16, "pt": "00" * 16,
                                                        "payloadLen": 128}]}]}]
                return super().request(method, path, token, body)

        class RejectingCtr:
            def ctr(self, key, iv, payload):
                raise ValueError("sensitive-native-internal-text")

        server = ValidCtrVector()
        cipher = Oracle()
        cipher.aes = RejectingCtr()
        report = client.execute(
            server, cipher, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            (client.AES_CTR,), poll_count=1)
        self.assertEqual(report["status"], "FAIL_OR_UNSUPPORTED_VECTOR")
        result = report["vectors"][0]
        self.assertEqual(result["stage"], "BUILD_RESPONSE")
        self.assertEqual(result["diagnostic_code"], "UNCLASSIFIED_VALUE_ERROR")
        self.assertNotIn("sensitive-native-internal-text", str(report))
        self.assertNotIn("private-session-token", str(report))

    def test_aes_gcm_rejected_group_has_sanitized_diagnostic_code(self):
        """Bad GCM AFT length must fail without disclosing test material."""
        class BadGcmVector(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    return [{"acvVersion": "1.0"},
                            {"vsId": 91, "algorithm": client.AES_GCM, "revision": "1.0",
                             "testGroups": [{"tgId": 7, "testType": "AFT",
                                             "direction": "encrypt", "keyLen": 128,
                                             "ivGen": "external", "ivLen": 96,
                                             "tagLen": 128, "payloadLen": 256, "aadLen": 0,
                                             "tests": [{"tcId": 8, "key": "00" * 16,
                                                        "iv": "00" * 12, "aad": "",
                                                        "pt": "00" * 16}]}]}]
                return super().request(method, path, token, body)

        server = BadGcmVector()
        cipher = Oracle()
        cipher.aes = object()
        report = client.execute(
            server, cipher, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            (client.AES_ECB, client.AES_GCM), poll_count=1)
        self.assertEqual(report["status"], "FAIL_OR_UNSUPPORTED_VECTOR")
        result = report["vectors"][0]
        self.assertEqual(result["stage"], "BUILD_RESPONSE")
        self.assertEqual(result["reason"], "ValueError")
        self.assertEqual(result["diagnostic_code"], "PAYLOAD_LENGTH")
        self.assertNotIn("private-login-token", str(report))
        self.assertNotIn("private-session-token", str(report))
        self.assertFalse(any(method == "POST" and path == server.vector + "/results"
                             for method, path, token, body in server.calls))

    def test_aes_gcm_unknown_error_text_remains_private(self):
        """Unknown native AES-GCM errors are represented by an opaque code."""
        class ValidGcmVector(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    return [{"acvVersion": "1.0"},
                            {"vsId": 91, "algorithm": client.AES_GCM, "revision": "1.0",
                             "testGroups": [{"tgId": 7, "testType": "AFT",
                                             "direction": "encrypt", "keyLen": 128,
                                             "ivGen": "external", "ivLen": 96,
                                             "tagLen": 128, "payloadLen": 128, "aadLen": 0,
                                             "tests": [{"tcId": 8, "key": "00" * 16,
                                                        "iv": "00" * 12, "aad": "",
                                                        "pt": "00" * 16}]}]}]
                return super().request(method, path, token, body)

        class RejectingGcm:
            def transform(self, key, iv, aad, payload, tag=None):
                raise ValueError("sensitive-gcm-internal-text")

        server = ValidGcmVector()
        cipher = Oracle()
        cipher.aes = RejectingGcm()
        report = client.execute(
            server, cipher, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            (client.AES_ECB, client.AES_GCM), poll_count=1)
        self.assertEqual(report["status"], "FAIL_OR_UNSUPPORTED_VECTOR")
        result = report["vectors"][0]
        self.assertEqual(result["stage"], "BUILD_RESPONSE")
        self.assertEqual(result["diagnostic_code"], "UNCLASSIFIED_VALUE_ERROR")
        self.assertNotIn("sensitive-gcm-internal-text", str(report))
        self.assertNotIn("private-session-token", str(report))

    def test_mlkem_incomplete_registration_mode_fails_closed(self):
        """Submitting keyGen alone cannot satisfy an advertised encapDecap mode."""
        class KeyGenOnly(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    self.calls.append((method, path, token, body))
                    return [{"acvVersion": "1.0"},
                            {"vsId": 91, "algorithm": "ML-KEM", "mode": "keyGen",
                             "revision": "FIPS203",
                             "testGroups": [{"tgId": 1, "testType": "AFT",
                                             "parameterSet": "ML-KEM-512",
                                             "tests": [{"tcId": 1, "d": "AB" * 32,
                                                        "z": "CD" * 32}]}]}]
                return super().request(method, path, token, body)

        class NativeKem:
            def keygen(self, parameter, d, z):
                return b"\x01" * 800, b"\x02" * 1632

        server = KeyGenOnly()
        qsc = Oracle()
        qsc.kem = NativeKem()
        report = client.execute(
            server, qsc, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            ("SHA3-256", "SHA3-512", "SHAKE-128", "SHAKE-256", "ML-KEM"),
            poll_count=1)
        self.assertEqual(report["status"], "FAIL_INCOMPLETE_ALGORITHM_COVERAGE")
        self.assertEqual(report["missing_kem_modes"], ["encapDecap"])
        self.assertNotIn("private-session-token", str(report))
        self.assertFalse(any(method == "GET" and path == server.session + "/results"
                             for method, path, token, body in server.calls))

    def test_mlkem_unadvertised_group_reports_safe_diagnostic(self):
        """Unsupported ML-KEM key checks fail before running any native operation."""
        class UnadvertisedKem(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    self.calls.append((method, path, token, body))
                    return [{"acvVersion": "1.0"},
                            {"vsId": 91, "algorithm": "ML-KEM",
                             "mode": "encapDecap", "revision": "FIPS203-tr1",
                             "testGroups": [{"tgId": 1, "testType": "VAL",
                                             "parameterSet": "ML-KEM-512",
                                             "function": "encapsulationKeyCheck",
                                             "tests": [{"tcId": 9, "ek": "AB" * 800}]}]}]
                return super().request(method, path, token, body)

        server = UnadvertisedKem()
        qsc = Oracle()
        qsc.kem = object()
        report = client.execute(
            server, qsc, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            ("SHA3-256", "SHA3-512", "SHAKE-128", "SHAKE-256", "ML-KEM"),
            poll_count=1)
        self.assertEqual(report["status"], "FAIL_OR_UNSUPPORTED_VECTOR")
        self.assertEqual(report["vectors"][0]["diagnostic_code"],
                         "UNSUPPORTED_KEM_GROUP")
        self.assertEqual(report["vectors"][0]["stage"], "BUILD_RESPONSE")
        self.assertNotIn("private-session-token", str(report))
        self.assertFalse(any(method == "POST" and path == server.vector + "/results"
                             for method, path, token, body in server.calls))

    def test_mldsa_incomplete_registered_modes_fails_closed(self):
        """Key generation alone cannot cover advertised sigGen and sigVer."""
        class KeyGenOnly(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    self.calls.append((method, path, token, body))
                    return [{"acvVersion": "1.0"},
                            {"vsId": 91, "algorithm": "ML-DSA", "mode": "keyGen",
                             "revision": "FIPS204",
                             "testGroups": [{"tgId": 1, "testType": "AFT",
                                             "parameterSet": "ML-DSA-44",
                                             "tests": [{"tcId": 1, "seed": "ab" * 32}]}]}]
                return super().request(method, path, token, body)

        class SigningAdapter:
            def keygen(self, parameter, seed):
                return bytes([1]) * 1312, bytes([2]) * 2560

        server = KeyGenOnly()
        engine = Oracle()
        engine.dsa = SigningAdapter()
        report = client.execute(
            server, engine, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            ("SHAKE-128", "SHAKE-256", "ML-DSA"), poll_count=1)
        self.assertEqual(report["status"], "FAIL_INCOMPLETE_ALGORITHM_COVERAGE")
        self.assertEqual(report["missing_dsa_modes"], ["sigGen", "sigVer"])
        self.assertNotIn("private-session-token", str(report))
        self.assertFalse(any(method == "GET" and path == server.session + "/results"
                             for method, path, token, body in server.calls))

    def test_mldsa_unadvertised_signature_interface_has_safe_code(self):
        """ACVP preHash rejection must not serialize native or secret material."""
        class UnadvertisedSigning(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    self.calls.append((method, path, token, body))
                    return [{"acvVersion": "1.0"},
                            {"vsId": 91, "algorithm": "ML-DSA", "mode": "sigGen",
                             "revision": "FIPS204-tr1",
                             "testGroups": [{"tgId": 1, "testType": "AFT",
                                             "parameterSet": "ML-DSA-44",
                                             "signatureInterface": "external",
                                             "preHash": "preHash",
                                             "deterministic": True,
                                             "keyFormat": "expanded",
                                             "tests": [{"tcId": 1}]}]}]
                return super().request(method, path, token, body)

        server = UnadvertisedSigning()
        engine = Oracle()
        engine.dsa = object()
        report = client.execute(
            server, engine, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            ("SHAKE-128", "SHAKE-256", "ML-DSA"), poll_count=1)
        self.assertEqual(report["status"], "FAIL_OR_UNSUPPORTED_VECTOR")
        self.assertEqual(report["vectors"][0]["diagnostic_code"], "UNSUPPORTED_INTERFACE")
        self.assertEqual(report["vectors"][0]["stage"], "BUILD_RESPONSE")
        self.assertNotIn("private-session-token", str(report))
        self.assertFalse(any(method == "POST" and path == server.vector + "/results"
                             for method, path, token, body in server.calls))

    def test_slhdsa_incomplete_registered_modes_fails_closed(self):
        """KeyGen alone cannot qualify registered sigGen and sigVer."""
        class OnlyKeyGeneration(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    self.calls.append((method, path, token, body))
                    return [{"acvVersion": "1.0"},
                            {"vsId": 91, "algorithm": "SLH-DSA", "mode": "keyGen",
                             "revision": "FIPS205",
                             "testGroups": [{"tgId": 1, "testType": "AFT",
                                             "parameterSet": "SLH-DSA-SHAKE-128s",
                                             "tests": [{"tcId": 1, "skSeed": "ab" * 16,
                                                        "skPrf": "cd" * 16,
                                                        "pkSeed": "ef" * 16}]}]}]
                return super().request(method, path, token, body)

        class SlhAdapter:
            def keygen(self, parameter, sk_seed, sk_prf, pk_seed):
                return bytes([1]) * 32, bytes([2]) * 64

        server = OnlyKeyGeneration()
        engine = Oracle()
        engine.slh = SlhAdapter()
        report = client.execute(
            server, engine, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            ("SHAKE-256", "SLH-DSA"), poll_count=1)
        self.assertEqual(report["status"], "FAIL_INCOMPLETE_ALGORITHM_COVERAGE")
        self.assertEqual(report["missing_slh_modes"], ["sigGen", "sigVer"])
        self.assertNotIn("private-session-token", str(report))
        self.assertFalse(any(method == "GET" and path == server.session + "/results"
                             for method, path, token, body in server.calls))

    def test_slhdsa_unsupported_prehash_has_allowlisted_diagnostic(self):
        """Unsupported FIPS205 preHash cannot leak vector contents in evidence."""
        class BadSigningMode(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    self.calls.append((method, path, token, body))
                    return [{"acvVersion": "1.0"},
                            {"vsId": 91, "algorithm": "SLH-DSA", "mode": "sigGen",
                             "revision": "FIPS205",
                             "testGroups": [{"tgId": 1, "testType": "AFT",
                                             "parameterSet": "SLH-DSA-SHAKE-128s",
                                             "signatureInterface": "external",
                                             "preHash": "preHash",
                                             "deterministic": True,
                                             "tests": [{"tcId": 1}]}]}]
                return super().request(method, path, token, body)

        server = BadSigningMode()
        engine = Oracle()
        engine.slh = object()
        report = client.execute(
            server, engine, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
            ("SHAKE-256", "SLH-DSA"), poll_count=1)
        self.assertEqual(report["status"], "FAIL_OR_UNSUPPORTED_VECTOR")
        self.assertEqual(report["vectors"][0]["diagnostic_code"], "UNSUPPORTED_INTERFACE")
        self.assertEqual(report["vectors"][0]["stage"], "BUILD_RESPONSE")
        self.assertNotIn("private-session-token", str(report))
        self.assertFalse(any(method == "POST" and path == server.vector + "/results"
                             for method, path, token, body in server.calls))

    def test_large_response_uses_server_grant_and_single_upload(self):
        """Large responses use a grant rather than the standard result endpoint."""
        class LargeServer(FakeTransport):
            def __init__(self):
                super().__init__()
                self.uploads = []

            def request(self, method, path, token=None, body=None):
                if path == client.DEMO_API + "/login" and method == "POST":
                    self.calls.append((method, path, token, body))
                    return [{"acvVersion": "1.0"},
                            {"accessToken": "private-login-token",
                             "largeEndpointRequired": True, "sizeConstraint": 32}]
                if path == client.DEMO_API + "/large" and method == "POST":
                    self.calls.append((method, path, token, body))
                    self.grant_body = body
                    return [{"acvVersion": "1.0"},
                            {"url": "https://demo.acvts.nist.gov/large/mock-one-time-id",
                             "accessToken": "private-large-token"}]
                return super().request(method, path, token, body)

            def upload_large(self, url, token, body):
                self.uploads.append((url, token, body))

        server = LargeServer()
        report = client.execute(server, Oracle(),
                                "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                                ("SHA2-256",), poll_count=1)
        self.assertEqual(report["status"], "PASS_DEMO_SAMPLE")
        self.assertEqual(len(server.uploads), 1)
        self.assertEqual(server.uploads[0][1], "private-large-token")
        self.assertEqual(server.grant_body[1]["vectorSetUrl"], server.vector)
        self.assertGreater(server.grant_body[1]["submissionSize"], 32)
        self.assertFalse(any(method == "POST" and path == server.vector + "/results"
                             for method, path, token, body in server.calls))
        self.assertNotIn("private-large-token", str(report))

    def test_large_response_rejects_unavailable_upload_handler(self):
        """Missing authorized large transport must fail before server acceptance."""
        class NoUploadServer(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "POST" and path == client.DEMO_API + "/login":
                    return [{"acvVersion": "1.0"},
                            {"accessToken": "private-login-token",
                             "largeEndpointRequired": True, "sizeConstraint": 8}]
                if method == "POST" and path == client.DEMO_API + "/large":
                    return [{"acvVersion": "1.0"},
                            {"url": "https://not-approved.example/large/id"}]
                return super().request(method, path, token, body)

        server = NoUploadServer()
        report = client.execute(server, Oracle(),
                                "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                                ("SHA2-256",), poll_count=1)
        self.assertEqual(report["status"], "FAIL_OR_UNSUPPORTED_VECTOR")
        self.assertFalse(report["server_passed"])

    def test_large_upload_cross_origin_is_rejected_without_network_access(self):
        """Never send bearer tokens to an unapproved server-provided origin."""
        transport = object.__new__(client.DemoTransport)
        transport._large_origin = None
        body = [{"acvVersion": "1.0"}, {"vsId": 91}]
        with self.assertRaises(ValueError):
            transport.upload_large("https://attacker.example/large/1", "private", body)
        with self.assertRaises(ValueError):
            transport.upload_large("http://demo.acvts.nist.gov/large/1", "private", body)
        with self.assertRaises(ValueError):
            transport.upload_large("https://demo.acvts.nist.gov@attacker.example/large/1",
                                   "private", body)

    def test_transient_vector_get_retries_at_most_three_times(self):
        """429/503 responses are retryable only for idempotent GET requests."""
        class TransientGet(FakeTransport):
            def __init__(self):
                super().__init__()
                self.failures = 0

            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector and self.failures < 2:
                    self.failures += 1
                    raise client.AcvpTransient("server 503")
                return super().request(method, path, token, body)

        server = TransientGet()
        original_sleep = client.time.sleep
        client.time.sleep = lambda seconds: None
        try:
            report = client.execute(
                server, Oracle(),
                "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                ("SHA2-256",), poll_count=1)
        finally:
            client.time.sleep = original_sleep
        self.assertEqual(report["status"], "PASS_DEMO_SAMPLE")
        self.assertEqual(server.failures, 2)

    def test_transient_submission_is_never_replayed(self):
        """Ambiguous transient POST responses must fail closed, not resubmit."""
        class UnavailablePost(FakeTransport):
            def __init__(self):
                super().__init__()
                self.submissions = 0

            def request(self, method, path, token=None, body=None):
                if method == "POST" and path == self.vector + "/results":
                    self.submissions += 1
                    raise client.AcvpTransient("server 503")
                return super().request(method, path, token, body)

        server = UnavailablePost()
        report = client.execute(server, Oracle(),
                                "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                                ("SHA2-256",), poll_count=1)
        self.assertEqual(report["status"], "FAIL_OR_UNSUPPORTED_VECTOR")
        self.assertEqual(server.submissions, 1)

    def test_registration_is_byte_aligned_and_sample_only(self):
        registration = client.registration(("SHA2-256", "SHA3-256"))
        self.assertTrue(registration[1]["isSample"])
        self.assertEqual(registration[1]["algorithms"][1]["revision"], "2.0")
        self.assertEqual(registration[1]["algorithms"][0]["messageLength"][0]["increment"], 8)
        self.assertNotIn("performLargeDataTest", registration[1]["algorithms"][0])

    def test_hmac_and_shake_capabilities(self):
        selected = ("SHA2-256", "HMAC-SHA2-256", "SHAKE-256")
        capabilities = client.registration(selected)[1]["algorithms"]
        self.assertEqual(capabilities[1]["revision"], "2.0")
        self.assertEqual(capabilities[1]["macLen"][0]["max"], 256)
        self.assertEqual(capabilities[1]["prereqVals"][0]["valValue"], "same")
        self.assertEqual(capabilities[2]["revision"], "FIPS202")
        self.assertEqual(capabilities[2]["outputLen"][0]["increment"], 8)

    def test_hmac_requires_sha_prerequisite(self):
        with self.assertRaises(ValueError):
            client.registration(("HMAC-SHA2-256",))

    def test_registration_rejects_unsupported_algorithms(self):
        with self.assertRaises(ValueError):
            client.registration(("ML-DSA-44",))

    def test_rejects_cross_origin_and_parent_paths(self):
        for path in ("https://evil.test/acvp/v1/login", "//evil.test/acvp/v1/login",
                     "/acvp/v1/../login", "/acvp/v1/login?jwt=a", "/other/login"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                client.check_path(path)

    def test_session_execution_with_tokens_redacted_from_report(self):
        transport = FakeTransport()
        report = client.execute(transport, Oracle(), "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                                ("SHA2-256",), poll_count=1)
        self.assertEqual(report["status"], "PASS_DEMO_SAMPLE")
        self.assertEqual(report["test_session"], "42")
        self.assertNotIn("private-login-token", str(report))
        self.assertNotIn("private-session-token", str(report))
        self.assertEqual(transport.calls[2][2], "private-session-token")
        self.assertEqual(transport.calls[3][3][1]["testGroups"][0]["tests"][0]["md"], "AB" * 32)

    def test_unsupported_vector_is_never_submitted(self):
        transport = FakeTransport(test_type="LDT")
        report = client.execute(transport, Oracle(), "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                                ("SHA2-256",), poll_count=1)
        self.assertEqual(report["status"], "FAIL_OR_UNSUPPORTED_VECTOR")
        self.assertEqual(len(transport.calls), 3)
        self.assertNotIn("private-session-token", str(report))

    def test_final_verdict_replaces_stale_incomplete_poll_status(self):
        """Evidence must reflect the final server verdict, not an earlier poll."""
        class PendingThenPassing(FakeTransport):
            def __init__(self):
                super().__init__()
                self.polls = 0

            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.session + "/results":
                    self.polls += 1
                    if self.polls == 1:
                        return [{"acvVersion": "1.0"}, {"passed": False,
                                "results": [{"vectorSetUrl": self.vector,
                                             "status": "incomplete"}]}]
                return super().request(method, path, token, body)

        transport = PendingThenPassing()
        report = client.execute(transport, Oracle(),
                                "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                                ("SHA2-256",), poll_count=2, poll_sleep=0)
        self.assertEqual(report["status"], "PASS_DEMO_SAMPLE")
        self.assertTrue(report["server_passed"])
        self.assertEqual(report["verdict_poll_count"], 2)
        self.assertEqual(report["vector_verdict_statuses"], ["passed"])

    def test_demo_failure_verdict_is_not_promoted_to_pass(self):
        transport = FakeTransport(passes=False)
        report = client.execute(transport, Oracle(), "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                                ("SHA2-256",), poll_count=1)
        self.assertEqual(report["status"], "FAIL_DEMO_VERDICT")


    def test_partial_successful_server_verdict_does_not_pass(self):
        class PartialTransport(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.session + "/results":
                    return [{"acvVersion": "1.0"}, {"passed": True, "results": []}]
                return super().request(method, path, token, body)

        result = client.execute(PartialTransport(), Oracle(),
                                "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=", ("SHA2-256",), poll_count=1)
        self.assertEqual(result["status"], "FAIL_DEMO_VERDICT")
        self.assertFalse(result["server_passed"])

    def test_verdict_requires_exactly_one_result_per_vector(self):
        session = client.DEMO_API + "/testSessions/42"
        vectors = {session + "/vectorSets/91", session + "/vectorSets/92"}
        def response(entries, passed=True):
            return {"passed": passed, "results": entries}
        one = {"vectorSetUrl": session + "/vectorSets/91", "status": "passed"}
        two = {"vectorSetUrl": session + "/vectorSets/92", "status": "passed"}
        extra = {"vectorSetUrl": session + "/vectorSets/93", "status": "passed"}
        self.assertEqual(client.reconcile_verdict(response([one, two]), vectors), "PASS")
        self.assertEqual(client.reconcile_verdict(response([one]), vectors), "FAIL")
        self.assertEqual(client.reconcile_verdict(response([one, one, two]), vectors), "FAIL")
        self.assertEqual(client.reconcile_verdict(response([one, two, extra]), vectors), "FAIL")
        self.assertEqual(client.reconcile_verdict(response([one, {**two, "status": "incomplete"}]), vectors), "FAIL")
        self.assertEqual(client.reconcile_verdict(response([one], False), vectors), "PENDING")
        self.assertEqual(client.reconcile_verdict(response([one, {**two, "status": "failed"}], False), vectors), "FAIL")
        self.assertEqual(client.reconcile_verdict({"passed": "true", "results": [one, two]}, vectors), "FAIL")

    def test_duplicate_registration_vector_url_fails_before_processing(self):
        class DuplicateTransport(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "POST" and path == client.DEMO_API + "/testSessions":
                    return [{"acvVersion": "1.0"}, {"url": self.session,
                            "vectorSetUrls": [self.vector, self.vector],
                            "accessToken": "private-session-token"}]
                return super().request(method, path, token, body)

        server = DuplicateTransport()
        with self.assertRaisesRegex(ValueError, "duplicate vector-set URL"):
            client.execute(server, Oracle(), "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                           ("SHA2-256",), poll_count=1)
        self.assertFalse(any(method == "POST" and path.endswith("/results")
                             for method, path, _, _ in server.calls))

    def test_downloaded_vector_id_must_match_requested_id(self):
        class MismatchedTransport(FakeTransport):
            def request(self, method, path, token=None, body=None):
                result = super().request(method, path, token, body)
                if method == "GET" and path == self.vector:
                    result[1]["vsId"] = 99
                return result

        server = MismatchedTransport()
        report = client.execute(server, Oracle(), "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                                ("SHA2-256",), poll_count=1)
        self.assertEqual(report["status"], "FAIL_OR_UNSUPPORTED_VECTOR")
        self.assertFalse(any(method == "POST" and path.endswith("/results")
                             for method, path, _, _ in server.calls))


    def test_ecc_session_cannot_pass_when_selected_modes_are_missing(self):
        class PartialEccTransport(FakeTransport):
            def request(self, method, path, token=None, body=None):
                if method == "GET" and path == self.vector:
                    return [{"acvVersion": "1.0"}, {"vsId": 91, "algorithm": "XECDH",
                            "mode": "keyVer", "revision": "RFC7748",
                            "testGroups": [{"tgId": 1, "testType": "AFT", "curve": "Curve25519",
                                            "tests": [{"tcId": 1, "publicKey": "09" + "00" * 31}]}]}]
                return super().request(method, path, token, body)

        class KeyVerifier:
            def xecdh_keyver(self, curve, value):
                return True

        oracle = Oracle()
        oracle.ecc = KeyVerifier()
        server = PartialEccTransport()
        report = client.execute(server, oracle, "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                                ("XECDH",), poll_count=1, drbg_validation="DRBG-TEST-ID")
        self.assertEqual(report["status"], "FAIL_INCOMPLETE_ALGORITHM_COVERAGE")
        self.assertEqual(report["missing_algorithms"], [])
        self.assertEqual(report["missing_ecc_modes"], ["XECDH/SSC", "XECDH/keyGen"])
        self.assertFalse(any(method == "GET" and path == server.session + "/results"
                             for method, path, _, _ in server.calls))

    def test_sample_cannot_pass_with_missing_algorithm_vectors(self):
        server = FakeTransport()
        report = client.execute(server, Oracle(), "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=",
                                ("SHA2-256", "SHA3-256"), poll_count=1)
        self.assertEqual(report["status"], "FAIL_INCOMPLETE_ALGORITHM_COVERAGE")
        self.assertEqual(report["missing_algorithms"], ["SHA3-256"])
        self.assertFalse(report["server_passed"])
        self.assertFalse(any(method == "GET" and path == server.session + "/results"
                             for method, path, _, _ in server.calls))


if __name__ == "__main__":
    unittest.main()
