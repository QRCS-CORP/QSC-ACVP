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

    def test_nist_xecdh_all_published_keyver_samples(self):
        """Require native QSC to match all NIST RFC7748 sample KeyVer verdicts."""
        groups = (
            ("Curve25519", (
                (1, "A1BB764A157C6EF2430D53DF1DE26A1A41F17DCF0318E62BE2F589D2D9D78E82", True),
                (2, "E2ECE75B2373C11D47A07EA38A82D4407A5E6EDFF635F1D76F74D39412E8F05D", True),
                (3, "746F8A2F591F29FB2439CF62482AA2BC62A6C759F30CE2D9FF1CC15DADE9705C", True),
                (4, "2EA0E1B60D13800BF8A61F49CE5E918CD41A7778BF8C4F698F30DCD03E8AB85FFF", False),
                (5, "80C84AB203B1F280E1D83611B1E9B092A684D9D625784348EE92998BC95B1FF0", True),
                (6, "88EFAA909B2A968C5D3A5F5C1AFD97D37F751C724832EB6E741A152844921925FF", False),
                (7, "3B92AC5D780F27A4FDBF3AD262723458B698BE7DBE2D61002377085AEC5C5F", False),
                (8, "02961EF1E9E6E1F37BA0A4BA6ED6F8038F4FFC27CA9C3A66E25B1548C1F94C2EFF", False),
                (9, "52D5F0F84FE6707C975AC1FAF5D895B296A599F5C132A249D722593F29E916", False),
                (10, "05634C7CAAB59A4D4832266C32BC287F12F3D92C8B89140B980CC0CB5E3639FC", True),
                (11, "2676703A8AF06E1B989D82C960076A561140D7211D01741F5329687C04EC7321", True),
                (12, "8F049144AEF72B3A863FA3F9C50BE473726D89B371EDF3D113B844B9AFF47141FF", False),
                (13, "BAC8024155DEA2C04E88704E5128A081FF4D5188A23174EC7661B71D13DB5D", False),
                (14, "7B74C87D18140CAD4CA997CE2F890BA973D5B232D181E310E9FA762D3D856FCA", True),
                (15, "432C6D366D2B5AB1A089D727F89544E566A0006670062680D075064BA69D3A", False),
                (16, "E489A83574236CFC40D68EBC5998F7B58C0C69D1C3A8185F112A225E9409FB6D", True),
            )),
            ("Curve448", (
                (17, "A620D43909A56773AC300DB9F3A80DEDDE366339AEF838F76CF82929E7603448873958926F0C0611BCFED3F3FBA1BE2A9FA17E4B12AB5450", True),
                (18, "B630DC718AF740E4B8C2363286056F9B64300A4DEFBBEE29CB51BC0870109B227C0E33F548E4C61C60587DF85470A252E903EB18C9F8032EFF", False),
                (19, "8CD280502422229B770ACA8FDF77C925BDBEC54F4540BC06C6AD85B8A1FCF41461B8D44507689A6CB8A8615C6512DD5CA7A6F49B77E1F2", False),
                (20, "F24BB8338870256EDE71515C6D775716FA553D7425C5C08DAD37CBB3EDA8CFA16A6C4662C51D19F76BDB97078F48AFC6B05E857BA8F96EB8", True),
                (21, "9F4548DB4C6528F7CD91CBB1426A648BF8B29C236527767C843CDFA4943D6C5F6344CB4237EDB2150FC1E6FC70620720BDE26F899B7A2399FF", False),
                (22, "DAB7319311BD4D4F9843C309059318A7423CCFB184B082CFAD5DD9D7F2C8D1C4FC52A5A2012B6EBD77FF487E348AA4C9FCE94545F3865069", True),
                (23, "00E3304DA8DD8B85297A95B9C1A21F4F6C48E66384B745FF628A0CBDA064B9AA962649897B89345C28A096673A855C21B25C2D5469230936", True),
                (24, "5D0C60536EBE2BED686157957682A62C933DE097F1AEB996143514EDF7FBEF54C73C1A62BCDF94E3486AC5F320CA4C9F0BCA1A8A645024", False),
                (25, "038072FA6F177856EE148A76AF9A4C85AC46BDE1338437E11206B209E2FE7BD52B22064029EF3431072B4E432213E430B7F3A679BB5A5B40FF", False),
                (26, "F0D50116AF56BB82A9F05A68744F34EE6F8BDCDB5BA63881C90B85F67C294B24436DF5354C63B1253AB5229895C6D8C98DB1C1DB8CDF9AEE", True),
                (27, "9192FBCF4789625DCE23446EAF3B7DC1DAD7CDC98D62EDB226FA442E1821C0EF1C27900BBF25C3486276BE18A1AF286AF2D34EF6D7901F", False),
                (28, "B18AE3E4EDF4F2724152E285CA3B778FEA3F153708EEA04AF5D171A45F3CFD4C3CB37488E81992A229AA1E9D2B0B9AC2810D802D12C7EE", False),
                (29, "542D7A09741C38282108E2DA42485A5CCA3DC85F8650D9DA3FDF1A2EC083DFFD3B63DCD305B4ED3A81EDE4ADF959B008256F74A3CA333210FF", False),
                (30, "8B0BBB360429474E52CED258B8A07B44A6388851A116202C887696B9F3E7FF7903AEA7E4C21219AD37D8036506D6B34564A178072AB5B5E7", True),
                (31, "C147888FAB6438C83A8C688C5E5170CF8ADBDDFB2E259DD1242082F6BECC9B7B3FB45E5DD642FC642E7A4C208C2B1CBAFFDBD504D1262E6A", True),
                (32, "933A135C648E21FB080041157B38AF29BACA9EB4A01278F64B1A9F1C855A7E35D4E882700077455111D46421A41E47C96D6A70A1FA745A31", True),
            )),
        )
        for curve, samples in groups:
            with self.subTest(curve=curve):
                passes = 0
                for case_id, public_hex, expected in samples:
                    actual = self.ecc.xecdh_keyver(curve, bytes.fromhex(public_hex))
                    self.assertEqual(
                        actual, expected,
                        f"FAIL: native XECDH NIST {curve} keyVer tcId {case_id}")
                    passes += int(actual)
                self.assertEqual(passes, 8,
                                 f"FAIL: native NIST {curve} accepted key count")

    def test_hcg_xecdh_nist_ssc_public_inputs_against_independent_oracle(self):
        """QSC SSC with NIST server points must equal RFC7748 reference exchange."""
        class ReproducibleSource:
            def generate(self, length):
                return bytes(range(length))

        source = QscEcc(self.ecc_path, require_complete=True,
                        rng=ReproducibleSource())
        groups = (
            ("Curve25519", (
                "42C4060DF475A484E4236D10F17180AF3B99F6D684DDF870E845881B9071A54E",
                "6F816BF7D5F9A0A1D9455D41A02CFFF189809ADA9DDFB2715C34BBB5F0947603",
                "B11FADD796461DBB7B4744C8D120AB417BA0BCB4D07C19BAC5D35A5A63E1262E",
                "9E50A0F910DF7272063F56E6C1FA0985D67EEDB27A614F1B50F169E553BF6935",
            )),
            ("Curve448", (
                "88FF31342DDA1FE5228513EA80F31B2F7D749A55FC13770B225DA68A27215C6BE67AF192B92F12AE01475134DBE5BA981EC1EC84ED4A6214",
                "585034D7E552FAABE3BC7C88ECC6B16385FD74A8895F1E755C5E2F116EE0EB21D3FA581283B6962FA6408DDBF9EFA9110ECCEAFEA1B7507B",
                "783A656767DE7A13C4019903C0ED8A426DD5DD38B0E8424FC27633A36AD2D892257FA957166FA1DDBC54C56445E942B1D22B8D8F4059C9A5",
                "2F803986C99567F191C0A0614A722D4152CCB8DF2DA481E09FF64CDDD259E8CFCBCCFA51A11885B10358301316A38F402A094D13E97CD34C",
            )),
        )
        for curve, server_points in groups:
            with self.subTest(curve=curve):
                size = 32 if curve == "Curve25519" else 56
                native_private = (x25519.X25519PrivateKey if size == 32
                                  else x448.X448PrivateKey)
                native_public = (x25519.X25519PublicKey if size == 32
                                 else x448.X448PublicKey)
                independent = native_private.from_private_bytes(bytes(range(size)))
                independent_public = independent.public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                for case_id, public_hex in enumerate(server_points, 1):
                    public_iut, z = source.xecdh_ssc(curve, bytes.fromhex(public_hex))
                    self.assertEqual(
                        public_iut, independent_public,
                        f"FAIL: NIST XECDH {curve} SSC local public key case {case_id}")
                    expected = independent.exchange(
                        native_public.from_public_bytes(bytes.fromhex(public_hex)))
                    self.assertEqual(
                        z, expected,
                        f"FAIL: NIST XECDH {curve} SSC secret case {case_id}")

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
