"""Unsupported PQ capability and vector-set forms must always fail closed."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo_client import registration
from mldsa_client import PARAMETERS as MLDSA_PARAMETERS, build_mldsa_response
from slhdsa_client import PARAMETERS as SLH_PARAMETERS, build_slhdsa_response
from local_client import build_response


class FakeDsa:
    def keygen(self, name, seed):
        return b"\x01" * 1312, b"\x02" * 2560

    def sign(self, name, sk, message, context):
        return b"\x03" * 2420

    def verify(self, name, pk, message, context, signature):
        return signature[0] == 3


class FakeSlh:
    def keygen(self, name, skseed, skprf, pkseed):
        return b"\x01" * 32, b"\x02" * 64

    def sign(self, name, sk, message, context):
        return b"\x03" * 7856

    def verify(self, name, pk, message, context, signature):
        return len(signature) == 7856


def vector(algorithm, mode, revision, group):
    return [{"acvVersion": "1.0"}, {"vsId": 7, "algorithm": algorithm,
            "mode": mode, "revision": revision, "testGroups": [group]}]


class PqVectorModeTests(unittest.TestCase):
    def test_registration_is_restricted_to_supported_signature_interfaces(self):
        selection = ("SHA2-256", "SHA3-256", "SHA3-512", "SHAKE-128", "SHAKE-256",
                     "ML-KEM", "ML-DSA", "SLH-DSA")
        caps = registration(selection)[1]["algorithms"]
        self.assertEqual(len(caps), 13)
        for algorithm in ("ML-DSA", "SLH-DSA"):
            signing = next(c for c in caps if c.get("algorithm") == algorithm and c.get("mode") == "sigGen")
            self.assertEqual(signing["signatureInterfaces"], ["external"])
            self.assertEqual(signing["preHash"], ["pure"])
            self.assertEqual(signing["deterministic"], [True])

    def test_ml_dsa_seeded_keygen_vector(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-DSA-44",
                 "tests": [{"tcId": 1, "seed": "AB" * 32}]}
        actual = build_mldsa_response(vector("ML-DSA", "keyGen", "FIPS204", group), FakeDsa())
        self.assertEqual(len(actual[1]["testGroups"][0]["tests"][0]["pk"]), 2624)

    def test_ml_dsa_rejects_randomized_siggen(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-DSA-44",
                 "signatureInterface": "external", "preHash": "pure", "deterministic": False,
                 "keyFormat": "expanded", "tests": []}
        with self.assertRaises(ValueError):
            build_mldsa_response(vector("ML-DSA", "sigGen", "FIPS204-tr1", group), FakeDsa())

    def test_ml_dsa_rejects_internal_mu_siggen(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-DSA-44",
                 "signatureInterface": "internal", "externalMu": True, "deterministic": True,
                 "keyFormat": "expanded", "tests": []}
        with self.assertRaises(ValueError):
            build_mldsa_response(vector("ML-DSA", "sigGen", "FIPS204-tr1", group), FakeDsa())

    def test_mldsa_registration_requires_both_shake_prerequisites(self):
        """ACVP ML-DSA advertises all three modes with same-session SHAKE."""
        required = ("SHAKE-128", "SHAKE-256")
        for missing in required:
            selected = tuple(x for x in required if x != missing) + ("ML-DSA",)
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                registration(selected)
        caps = registration(required + ("ML-DSA",))[1]["algorithms"][-3:]
        self.assertEqual([c["mode"] for c in caps], ["keyGen", "sigGen", "sigVer"])
        self.assertEqual([c["revision"] for c in caps],
                         ["FIPS204", "FIPS204-tr1", "FIPS204"])
        for capability in caps:
            self.assertEqual(capability["prereqVals"],
                             [{"algorithm": "SHA", "valValue": "same"}])

    def test_mldsa_multigroup_keygen_parameter_sizes(self):
        """One FIPS 204 vector set may contain all three parameter sets."""
        class QualifiedDsa:
            def keygen(self, name, seed):
                return (b"\x11" * MLDSA_PARAMETERS[name][1],
                        b"\x22" * MLDSA_PARAMETERS[name][2])
        groups = [{"tgId": index, "testType": "AFT", "parameterSet": name,
                   "tests": [{"tcId": index + 20, "seed": "01" * 32}]}
                  for index, name in enumerate(MLDSA_PARAMETERS, 1)]
        request = vector("ML-DSA", "keyGen", "FIPS204", groups[0])
        request[1]["testGroups"] = groups
        answer = build_mldsa_response(request, QualifiedDsa())[1]["testGroups"]
        self.assertEqual([g["tgId"] for g in answer], [1, 2, 3])
        for requested, actual in zip(groups, answer):
            name = requested["parameterSet"]
            self.assertEqual(actual["tests"][0]["tcId"], requested["tests"][0]["tcId"])
            self.assertEqual(len(actual["tests"][0]["pk"]), MLDSA_PARAMETERS[name][1] * 2)
            self.assertEqual(len(actual["tests"][0]["sk"]), MLDSA_PARAMETERS[name][2] * 2)

    def test_mldsa_multigroup_pure_signing_context_boundaries(self):
        """Deterministic external pure sigGen accepts empty and 255-byte context."""
        class QualifiedDsa:
            def sign(self, name, sk, message, context):
                return b"\xA6" * MLDSA_PARAMETERS[name][3]
        groups = []
        for index, name in enumerate(MLDSA_PARAMETERS, 1):
            groups.append({"tgId": index, "testType": "AFT", "parameterSet": name,
                           "signatureInterface": "external", "preHash": "pure",
                           "deterministic": True, "keyFormat": "expanded",
                           "tests": [
                               {"tcId": index * 10, "sk": "33" * MLDSA_PARAMETERS[name][2],
                                "message": "01", "context": ""},
                               {"tcId": index * 10 + 1,
                                "sk": "33" * MLDSA_PARAMETERS[name][2],
                                "message": "ab" * 32, "context": "ff" * 255}]})
        request = vector("ML-DSA", "sigGen", "FIPS204-tr1", groups[0])
        request[1]["testGroups"] = groups
        result = build_mldsa_response(request, QualifiedDsa())[1]["testGroups"]
        self.assertEqual([g["tgId"] for g in result], [1, 2, 3])
        for original, actual in zip(groups, result):
            self.assertEqual([a["tcId"] for a in actual["tests"]],
                             [t["tcId"] for t in original["tests"]])
            for item in actual["tests"]:
                self.assertEqual(len(item["signature"]),
                                 MLDSA_PARAMETERS[original["parameterSet"]][3] * 2)

    def test_mldsa_multigroup_pure_verification_valid_and_invalid(self):
        """ACVP sigVer AFT supplies testPassed for each signature independently."""
        class QualifiedDsa:
            def verify(self, name, pk, message, context, signature):
                return signature[0] == 0xA6
        groups = []
        for index, name in enumerate(MLDSA_PARAMETERS, 1):
            groups.append({"tgId": index, "testType": "AFT", "parameterSet": name,
                           "signatureInterface": "external", "preHash": "pure",
                           "tests": [
                               {"tcId": 3 * index, "pk": "11" * MLDSA_PARAMETERS[name][1],
                                "message": "ab", "context": "",
                                "signature": "a6" * MLDSA_PARAMETERS[name][3]},
                               {"tcId": 3 * index + 1,
                                "pk": "11" * MLDSA_PARAMETERS[name][1],
                                "message": "ab", "context": "01",
                                "signature": "00" * MLDSA_PARAMETERS[name][3]}]})
        request = vector("ML-DSA", "sigVer", "FIPS204", groups[0])
        request[1]["testGroups"] = groups
        actual = build_mldsa_response(request, QualifiedDsa())[1]["testGroups"]
        for group in actual:
            self.assertEqual([entry["testPassed"] for entry in group["tests"]],
                             [True, False])

    def test_mldsa_rejects_zero_length_message_and_unsupported_forms(self):
        """Do not accept unadvertised empty messages, preHash or seed key format."""
        valid = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-DSA-44",
                 "signatureInterface": "external", "preHash": "pure",
                 "deterministic": True, "keyFormat": "expanded",
                 "tests": [{"tcId": 1, "sk": "22" * 2560,
                            "message": "", "context": ""}]}
        with self.assertRaisesRegex(ValueError, "message outside registered length"):
            build_mldsa_response(
                vector("ML-DSA", "sigGen", "FIPS204-tr1", valid), FakeDsa())
        for key, value in (("preHash", "preHash"), ("keyFormat", "seed"),
                           ("deterministic", False), ("signatureInterface", "internal")):
            group = dict(valid)
            group[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                build_mldsa_response(
                    vector("ML-DSA", "sigGen", "FIPS204-tr1", group), FakeDsa())

    def test_mldsa_rejects_mismatched_revisions_and_invalid_context(self):
        """Revisions and context bounds must match registered ACVP capabilities."""
        for mode, revision in (("keyGen", "FIPS204-tr1"), ("sigGen", "FIPS204"),
                               ("sigVer", "FIPS204-tr1")):
            group = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-DSA-44",
                     "tests": []}
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                build_mldsa_response(vector("ML-DSA", mode, revision, group), FakeDsa())
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-DSA-44",
                 "signatureInterface": "external", "preHash": "pure",
                 "deterministic": True, "keyFormat": "expanded",
                 "tests": [{"tcId": 1, "sk": "22" * 2560, "message": "ab",
                            "context": "00" * 256}]}
        with self.assertRaises(ValueError):
            build_mldsa_response(
                vector("ML-DSA", "sigGen", "FIPS204-tr1", group), FakeDsa())

    def test_slhdsa_seeded_keygen_vector(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "SLH-DSA-SHAKE-128s",
                 "tests": [{"tcId": 1, "skSeed": "AB" * 16, "skPrf": "CD" * 16,
                            "pkSeed": "EF" * 16}]}
        actual = build_slhdsa_response(vector("SLH-DSA", "keyGen", "FIPS205", group), FakeSlh())
        self.assertEqual(len(actual[1]["testGroups"][0]["tests"][0]["sk"]), 128)

    def test_slhdsa_rejects_nondeterministic_signatures(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "SLH-DSA-SHAKE-128s",
                 "signatureInterface": "external", "preHash": "pure", "deterministic": False,
                 "tests": []}
        with self.assertRaises(ValueError):
            build_slhdsa_response(vector("SLH-DSA", "sigGen", "FIPS205", group), FakeSlh())

    def test_slhdsa_rejects_prehash(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "SLH-DSA-SHAKE-128s",
                 "signatureInterface": "external", "preHash": "preHash", "tests": []}
        with self.assertRaises(ValueError):
            build_slhdsa_response(vector("SLH-DSA", "sigVer", "FIPS205", group), FakeSlh())

    def test_slhdsa_registration_requires_shake256_prerequisite(self):
        """FIPS205 SHAKE-only registrations require SHAKE-256 in the session."""
        with self.assertRaises(ValueError):
            registration(("SLH-DSA",))
        selected = ("SHAKE-256", "SLH-DSA")
        caps = registration(selected)[1]["algorithms"][-3:]
        self.assertEqual([x["mode"] for x in caps], ["keyGen", "sigGen", "sigVer"])
        self.assertEqual([x["revision"] for x in caps], ["FIPS205"] * 3)
        self.assertEqual(caps[0]["parameterSets"], list(SLH_PARAMETERS))
        for capability in caps:
            self.assertEqual(capability["prereqVals"],
                             [{"algorithm": "SHAKE", "valValue": "same"}])

    def test_slhdsa_multigroup_keygen_all_six_parameter_sets(self):
        """Preserve tcIds and exact expanded key sizes across all SHAKE sets."""
        class KeyGenerator:
            def keygen(self, name, sk_seed, sk_prf, pk_seed):
                return (bytes([1]) * SLH_PARAMETERS[name][1],
                        bytes([2]) * SLH_PARAMETERS[name][2])

        groups = []
        for index, name in enumerate(SLH_PARAMETERS, 1):
            seed_len = SLH_PARAMETERS[name][4] // 3
            groups.append({"tgId": index, "testType": "AFT", "parameterSet": name,
                           "tests": [{"tcId": index * 10, "skSeed": "aa" * seed_len,
                                      "skPrf": "bb" * seed_len,
                                      "pkSeed": "cc" * seed_len}]})
        request = vector("SLH-DSA", "keyGen", "FIPS205", groups[0])
        request[1]["testGroups"] = groups
        response = build_slhdsa_response(request, KeyGenerator())[1]["testGroups"]
        self.assertEqual([g["tgId"] for g in response], list(range(1, 7)))
        for source, answer in zip(groups, response):
            lengths = SLH_PARAMETERS[source["parameterSet"]]
            self.assertEqual(answer["tests"][0]["tcId"], source["tests"][0]["tcId"])
            self.assertEqual(len(answer["tests"][0]["pk"]), lengths[1] * 2)
            self.assertEqual(len(answer["tests"][0]["sk"]), lengths[2] * 2)

    def test_slhdsa_multigroup_signing_context_boundaries(self):
        """All six deterministic external-pure variants permit 0..255 context bytes."""
        class SigningAdapter:
            def sign(self, name, sk, message, context):
                return bytes([0xA6]) * SLH_PARAMETERS[name][3]

        groups = []
        for index, name in enumerate(SLH_PARAMETERS, 1):
            groups.append({"tgId": index, "testType": "AFT",
                           "parameterSet": name, "signatureInterface": "external",
                           "preHash": "pure", "deterministic": True,
                           "tests": [{"tcId": index * 10, "sk": "22" * SLH_PARAMETERS[name][2],
                                      "message": "01", "context": ""},
                                     {"tcId": index * 10 + 1,
                                      "sk": "22" * SLH_PARAMETERS[name][2],
                                      "message": "ab" * 32, "context": "cd" * 255}]})
        request = vector("SLH-DSA", "sigGen", "FIPS205", groups[0])
        request[1]["testGroups"] = groups
        result = build_slhdsa_response(request, SigningAdapter())[1]["testGroups"]
        self.assertEqual([g["tgId"] for g in result], list(range(1, 7)))
        for group_in, group_out in zip(groups, result):
            self.assertEqual([t["tcId"] for t in group_out["tests"]],
                             [t["tcId"] for t in group_in["tests"]])
            for item in group_out["tests"]:
                self.assertEqual(len(item["signature"]),
                                 SLH_PARAMETERS[group_in["parameterSet"]][3] * 2)

    def test_slhdsa_sigver_invalid_signatures_are_not_adapter_errors(self):
        """NIST invalid-signature cases return testPassed rather than aborting."""
        class Verifier:
            def verify(self, name, pk, message, context, signature):
                return bool(signature) and signature[0] == 0xA6

        groups = []
        for index, name in enumerate(SLH_PARAMETERS, 1):
            groups.append({"tgId": index, "testType": "AFT",
                           "parameterSet": name, "signatureInterface": "external",
                           "preHash": "pure",
                           "tests": [{"tcId": index * 2, "pk": "11" * SLH_PARAMETERS[name][1],
                                      "message": "ab", "context": "",
                                      "signature": "a6" * SLH_PARAMETERS[name][3]},
                                     {"tcId": index * 2 + 1,
                                      "pk": "11" * SLH_PARAMETERS[name][1],
                                      "message": "ab", "context": "01",
                                      "signature": "00" * SLH_PARAMETERS[name][3]}]})
        request = vector("SLH-DSA", "sigVer", "FIPS205", groups[0])
        request[1]["testGroups"] = groups
        result = build_slhdsa_response(request, Verifier())[1]["testGroups"]
        self.assertEqual(len(result), 6)
        for group in result:
            self.assertEqual([x["testPassed"] for x in group["tests"]], [True, False])

    def test_slhdsa_rejects_unadvertised_empty_message_randomized_prehash(self):
        """Do not process inputs excluded from the registered FIPS205 profile."""
        group = {"tgId": 1, "testType": "AFT",
                 "parameterSet": "SLH-DSA-SHAKE-128s",
                 "signatureInterface": "external", "preHash": "pure",
                 "deterministic": True,
                 "tests": [{"tcId": 1, "sk": "22" * 64, "message": "", "context": ""}]}
        with self.assertRaisesRegex(ValueError, "message outside registered length"):
            build_slhdsa_response(vector("SLH-DSA", "sigGen", "FIPS205", group),
                                  FakeSlh())
        for key, invalid in (("preHash", "preHash"), ("deterministic", False),
                             ("signatureInterface", "internal")):
            bad = dict(group)
            bad[key] = invalid
            with self.subTest(key=key), self.assertRaises(ValueError):
                build_slhdsa_response(
                    vector("SLH-DSA", "sigGen", "FIPS205", bad), FakeSlh())
        bad = dict(group)
        bad["tests"] = [{"tcId": 1, "sk": "22" * 64, "message": "ab",
                         "context": "ff" * 256}]
        with self.assertRaises(ValueError):
            build_slhdsa_response(vector("SLH-DSA", "sigGen", "FIPS205", bad),
                                  FakeSlh())

    def test_global_dispatch_requires_configured_signature_libraries(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-DSA-44", "tests": []}
        with self.assertRaises(ValueError):
            build_response(vector("ML-DSA", "keyGen", "FIPS204", group), object())
        group["parameterSet"] = "SLH-DSA-SHAKE-128s"
        with self.assertRaises(ValueError):
            build_response(vector("SLH-DSA", "keyGen", "FIPS205", group), object())


if __name__ == "__main__":
    unittest.main()
