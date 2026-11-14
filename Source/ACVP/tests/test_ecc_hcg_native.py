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

"""HCG-backed native ECC ACVP interoperability with independent curve oracles."""

import os
from pathlib import Path
import sys
import unittest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, x25519, x448
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from drbg_client import QscDrbg
from ecc_client import QscEcc, CURVE_ORDERS


class EccHcgNativeTests(unittest.TestCase):
    """Require source-pinned QSC ECC and HCG shared libraries for every test."""

    @classmethod
    def setUpClass(cls):
        cls.ecc_path = Path(os.environ["QSC_ACVP_ECC_LIBRARY"])
        cls.drbg_path = Path(os.environ["QSC_ACVP_DRBG_LIBRARY"])
        if not cls.ecc_path.is_file() or not cls.drbg_path.is_file():
            raise RuntimeError("Native ECC and HCG qualification libraries are mandatory")

    def setUp(self):
        self.drbg = QscDrbg(self.drbg_path, "hcg")
        self.drbg.instantiate(bytes(range(32)), bytes(range(32, 48)))
        self.ecc = QscEcc(self.ecc_path, require_complete=True, rng=self.drbg)

    def tearDown(self):
        self.drbg.dispose()

    def test_hcg_ecdsa_keygen_matches_independent_curves(self):
        for curve, reference, size in (
                ("P-256", ec.SECP256R1(), 32),
                ("P-384", ec.SECP384R1(), 48),
                ("P-521", ec.SECP521R1(), 66)):
            with self.subTest(curve=curve):
                scalar, public = self.ecc.ecdsa_keygen(curve)
                private = ec.derive_private_key(int.from_bytes(scalar, "big"), reference)
                point = private.public_key().public_numbers()
                self.assertEqual(public, point.x.to_bytes(size, "big") +
                                 point.y.to_bytes(size, "big"),
                                 f"FAIL: HCG-backed QSC ECDSA keygen {curve}")

    def test_hcg_eddsa_keygen_matches_independent_curves(self):
        for curve, parser in (("ED-25519", ed25519.Ed25519PrivateKey),
                              ("ED-448", ed448.Ed448PrivateKey)):
            with self.subTest(curve=curve):
                seed, public = self.ecc.eddsa_keygen(curve)
                expected = parser.from_private_bytes(seed).public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                self.assertEqual(public, expected,
                                 f"FAIL: HCG-backed QSC EdDSA keygen {curve}")

    def test_hcg_xecdh_keygen_matches_independent_curves(self):
        for curve, parser in (("Curve25519", x25519.X25519PrivateKey),
                              ("Curve448", x448.X448PrivateKey)):
            with self.subTest(curve=curve):
                scalar, public = self.ecc.xecdh_keygen(curve)
                expected = parser.from_private_bytes(scalar).public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                self.assertEqual(public, expected,
                                 f"FAIL: HCG-backed QSC XECDH keygen {curve}")

    def test_hcg_ecdsa_scalar_rejection_is_unbiased(self):
        order = CURVE_ORDERS["P-256"]

        class RejectingSource:
            def __init__(self):
                self.calls = 0

            def generate(self, width):
                self.calls += 1
                self_count = self.calls
                if self_count == 1:
                    return bytes(width)
                if self_count == 2:
                    return order.to_bytes(width, "big")
                return (1).to_bytes(width, "big")

        source = RejectingSource()
        ecc = QscEcc(self.ecc_path, require_complete=True, rng=source)
        scalar, public = ecc.ecdsa_keygen("P-256")
        self.assertEqual(scalar, (1).to_bytes(32, "big"),
                         "FAIL: ECDSA rejection sampler must accept scalar one")
        self.assertEqual(source.calls, 3,
                         "FAIL: ECDSA rejection must discard zero and n")
        self.assertTrue(ecc.ecdsa_keyver("P-256", public),
                        "FAIL: accepted private scalar must yield valid QSC public key")

    def test_hcg_rng_short_read_fails_closed(self):
        class ShortSource:
            def generate(self, length):
                return bytes(length - 1)

        ecc = QscEcc(self.ecc_path, require_complete=True, rng=ShortSource())
        with self.assertRaises(ValueError, msg="FAIL: short DRBG output must be rejected"):
            ecc.ecdsa_keygen("P-256")

    def test_hcg_ecdsa_eddsa_signatures_verify_independently(self):
        message = b"HCG native ECC qualification"
        public, signatures = self.ecc.ecdsa_sign_group("P-256", [message])
        key = ec.EllipticCurvePublicNumbers(
            int.from_bytes(public[:32], "big"), int.from_bytes(public[32:], "big"),
            ec.SECP256R1()).public_key()
        signature = encode_dss_signature(int.from_bytes(signatures[0][0], "big"),
                                         int.from_bytes(signatures[0][1], "big"))
        key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        self.assertEqual(len(signatures), 1,
                         "FAIL: HCG-backed deterministic ECDSA signature count")
        public, signatures = self.ecc.eddsa_sign_group("ED-25519", [message])
        ed25519.Ed25519PublicKey.from_public_bytes(public).verify(signatures[0], message)
        self.assertEqual(len(signatures), 1,
                         "FAIL: HCG-backed Ed25519 signature count")

    def test_hcg_detecdsa_repeated_messages_are_deterministic_all_curves(self):
        """Every advertised DetECDSA curve must repeat r and s for one key/message."""
        message = b"NIST ACVP deterministic ECDSA with HCG"
        for curve, reference, digest, width in (
                ("P-256", ec.SECP256R1(), hashes.SHA256(), 32),
                ("P-384", ec.SECP384R1(), hashes.SHA384(), 48),
                ("P-521", ec.SECP521R1(), hashes.SHA512(), 66)):
            with self.subTest(curve=curve):
                messages = [message, message, b"other deterministic vector"]
                public, signatures = self.ecc.ecdsa_sign_group(curve, messages)
                self.assertEqual(len(signatures), len(messages),
                                 f"FAIL: DetECDSA HCG signature count {curve}")
                self.assertEqual(signatures[0], signatures[1],
                                 f"FAIL: DetECDSA repeated signature differs {curve}")
                self.assertEqual(len(public), 2 * width,
                                 f"FAIL: DetECDSA public-key width {curve}")
                numbers = ec.EllipticCurvePublicNumbers(
                    int.from_bytes(public[:width], "big"),
                    int.from_bytes(public[width:], "big"), reference)
                verifying_key = numbers.public_key()
                for signed_message, (r, sig_s) in zip(messages, signatures):
                    self.assertEqual((len(r), len(sig_s)), (width, width),
                                     f"FAIL: DetECDSA signature scalar width {curve}")
                    signature = encode_dss_signature(
                        int.from_bytes(r, "big"), int.from_bytes(sig_s, "big"))
                    verifying_key.verify(signature, signed_message,
                                        ec.ECDSA(digest))

    def test_hcg_detecdsa_seeded_signature_reproducibility(self):
        """A new HCG instance with identical seed must reproduce QSC signing."""
        message = b"Same deterministic signing key and message"
        expected = self.ecc.ecdsa_sign_group("P-256", [message, b""])
        other_hcg = QscDrbg(self.drbg_path, "hcg")
        try:
            other_hcg.instantiate(bytes(range(32)), bytes(range(32, 48)))
            independent = QscEcc(self.ecc_path, require_complete=True, rng=other_hcg)
            actual = independent.ecdsa_sign_group("P-256", [message, b""])
            self.assertEqual(actual, expected,
                             "FAIL: DetECDSA seed replay changed public key or signatures")
        finally:
            other_hcg.dispose()

    def test_nist_eddsa_keyver_public_samples_both_curves(self):
        """Native QSC validation must match NIST's published positive/negative keys."""
        samples = (
            ("ED-25519", "5BC0D8831F8D7FB200E32DAF36C54BF2808E69D40BD48BD915DF585B2696C166", False),
            ("ED-25519", "CF1BD87814E4113E9CAB4D5B95A4F85EA04BAC9EB70053023B1D201A85225072", True),
            ("ED-25519", "EB0E59A5D0EC784B3EFC7E5A86DFBD244789E5B384A652A43DC0968974E83571", True),
            ("ED-25519", "FBB4F7945F521A5CB169883477E9DFAFA14767FD4D973D8FD3667C46253F5943", False),
            ("ED-448", "D74E406880F2BD2950D8AC5593AAC612D945EA7CA08DC1EF6BE7FE0BB61C3B0DDA563ED2B545919937B3174CB9826698F575B15DAC6B642A80", True),
            ("ED-448", "8DE82D8611D23882CEFC1C3BD13C1E5E3BAC0D1AAE908FFF0B0A5431B90BEF715F1160073C919B886BBDAF156FA051CA37022E8118B260FF00", False),
            ("ED-448", "BC17476D69799F0CDAAF4D730FBD7BE9078DE04A1B90A91938E994FFF14C029214DE2FD97D75A0A973BC106C6AF465D44C2EE0D32D4D4CBB00", True),
            ("ED-448", "480B6575633FEFAF3635EFA2294F2CBF1E8D49F6BC0CD8B8F5A91A0A59922BE33CDD837A3ACCAA419970CBE4A21A062CF37F839931CF17EE80", False),
        )
        for curve, public_hex, expected in samples:
            with self.subTest(curve=curve, prefix=public_hex[:12]):
                actual = self.ecc.eddsa_keyver(curve, bytes.fromhex(public_hex))
                self.assertEqual(actual, expected,
                                 f"FAIL: QSC native EDDSA NIST keyVer {curve} {public_hex[:12]}")

    def test_hcg_eddsa_bit_flip_signatures_distinct_and_verify(self):
        """Native HCG/QSC pure EdDSA BFT signatures change for bit-flipped messages."""
        messages = (b"\x6B\x96\x39\xCC", b"\x6B\x96\x39\xCD",
                    b"\x6B\x96\x39\xCE")
        for curve, parser in (("ED-25519", ed25519.Ed25519PublicKey),
                              ("ED-448", ed448.Ed448PublicKey)):
            with self.subTest(curve=curve):
                public, signatures = self.ecc.eddsa_sign_group(curve, messages)
                self.assertEqual(len(signatures), 3,
                                 f"FAIL: native EDDSA BFT signed message count {curve}")
                self.assertEqual(len(set(signatures)), len(messages),
                                 f"FAIL: native EDDSA bit flip did not change signature {curve}")
                key = parser.from_public_bytes(public)
                for message, signature in zip(messages, signatures):
                    key.verify(signature, message)

    def test_hcg_kas_and_xecdh_shared_secrets_verify_independently(self):
        server = ec.derive_private_key(7, ec.SECP256R1())
        point = server.public_key().public_numbers()
        server_pub = point.x.to_bytes(32, "big") + point.y.to_bytes(32, "big")
        client_pub, secret = self.ecc.ecdh_generate("P-256", server_pub)
        public = ec.EllipticCurvePublicNumbers(
            int.from_bytes(client_pub[:32], "big"),
            int.from_bytes(client_pub[32:], "big"),
            ec.SECP256R1()).public_key()
        expected = server.exchange(ec.ECDH(), public)
        self.assertEqual(secret, expected,
                         "FAIL: HCG-backed QSC P-256 KAS-ECC-SSC")

        for curve, parser_private, parser_public, width in (
                ("Curve25519", x25519.X25519PrivateKey, x25519.X25519PublicKey, 32),
                ("Curve448", x448.X448PrivateKey, x448.X448PublicKey, 56)):
            with self.subTest(curve=curve):
                server = parser_private.from_private_bytes(bytes(range(width)))
                server_pub = server.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                client_pub, secret = self.ecc.xecdh_ssc(curve, server_pub)
                expected = server.exchange(parser_public.from_public_bytes(client_pub))
                self.assertEqual(secret, expected,
                                 f"FAIL: HCG-backed QSC XECDH SSC {curve}")


if __name__ == "__main__":
    unittest.main()
