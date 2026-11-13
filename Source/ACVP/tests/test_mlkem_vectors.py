"""ACVP ML-KEM schema and fail-closed adapter tests (no secret output logging)."""

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo_client import registration
from mlkem_client import PARAMETERS, build_mlkem_response
from local_client import build_response


class FakeKem:
    def keygen(self, parameter, d, z):
        return b"\x01" * PARAMETERS[parameter][1], b"\x02" * PARAMETERS[parameter][2]

    def encapsulate(self, parameter, ek, m):
        return b"\x03" * PARAMETERS[parameter][3], b"\x04" * 32

    def decapsulate(self, parameter, dk, ct):
        return b"\x05" * 32


class FakeQsc:
    kem = FakeKem()


def request(mode, revision, group):
    return [{"acvVersion": "1.0"}, {"vsId": 101, "algorithm": "ML-KEM", "mode": mode,
            "revision": revision, "testGroups": [group]}]


class MlKemAdapterTests(unittest.TestCase):
    def test_registration_uses_only_implemented_functions(self):
        selected = ("SHA3-256", "SHA3-512", "SHAKE-128", "SHAKE-256", "ML-KEM")
        capabilities = registration(selected)[1]["algorithms"]
        self.assertEqual(len(capabilities), 6)
        self.assertEqual([entry["mode"] for entry in capabilities[-2:]], ["keyGen", "encapDecap"])
        self.assertEqual(capabilities[-2]["revision"], "FIPS203")
        self.assertEqual(capabilities[-1]["revision"], "FIPS203-tr1")
        self.assertEqual(capabilities[-1]["functions"], ["encapsulation", "decapsulation"])
        self.assertEqual(capabilities[-1]["keyFormats"], ["expanded"])

    def test_registration_refuses_missing_hash_prerequisites(self):
        with self.assertRaises(ValueError):
            registration(("ML-KEM",))

    def test_keygen_all_three_parameter_sets(self):
        for name in PARAMETERS:
            with self.subTest(parameter=name):
                group = {"tgId": 1, "testType": "AFT", "parameterSet": name,
                         "tests": [{"tcId": 2, "d": "AB" * 32, "z": "CD" * 32}]}
                result = build_mlkem_response(request("keyGen", "FIPS203", group), FakeKem())
                self.assertEqual(len(result[1]["testGroups"][0]["tests"][0]["ek"]),
                                 PARAMETERS[name][1] * 2)
                self.assertEqual(len(result[1]["testGroups"][0]["tests"][0]["dk"]),
                                 PARAMETERS[name][2] * 2)

    def test_encapsulation_all_three_parameter_sets(self):
        for name in PARAMETERS:
            with self.subTest(parameter=name):
                group = {"tgId": 1, "testType": "AFT", "parameterSet": name,
                         "function": "encapsulation", "tests": [
                             {"tcId": 3, "ek": "AB" * PARAMETERS[name][1], "m": "CD" * 32}]}
                result = build_mlkem_response(request("encapDecap", "FIPS203-tr1", group), FakeKem())
                answer = result[1]["testGroups"][0]["tests"][0]
                self.assertEqual(len(answer["c"]), PARAMETERS[name][3] * 2)
                self.assertEqual(len(answer["k"]), 64)

    def test_decapsulation_expanded_key(self):
        name = "ML-KEM-768"
        group = {"tgId": 1, "testType": "VAL", "parameterSet": name,
                 "function": "decapsulation", "keyFormat": "expanded", "tests": [
                     {"tcId": 3, "dk": "AB" * PARAMETERS[name][2],
                      "c": "CD" * PARAMETERS[name][3]}]}
        self.assertEqual(build_mlkem_response(
            request("encapDecap", "FIPS203-tr1", group), FakeKem()
        )[1]["testGroups"][0]["tests"][0]["k"], "05" * 32)

    def test_fails_closed_for_key_check(self):
        group = {"tgId": 1, "testType": "VAL", "parameterSet": "ML-KEM-512",
                 "function": "encapsulationKeyCheck", "tests": []}
        with self.assertRaises(ValueError):
            build_mlkem_response(request("encapDecap", "FIPS203-tr1", group), FakeKem())

    def test_fails_closed_for_seed_format(self):
        group = {"tgId": 1, "testType": "VAL", "parameterSet": "ML-KEM-512",
                 "function": "decapsulation", "keyFormat": "seed", "tests": []}
        with self.assertRaises(ValueError):
            build_mlkem_response(request("encapDecap", "FIPS203-tr1", group), FakeKem())

    def test_fails_closed_for_unsupported_revision(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-KEM-512", "tests": []}
        with self.assertRaises(ValueError):
            build_mlkem_response(request("keyGen", "FIPS203-future", group), FakeKem())

    def test_fails_closed_on_short_hex_input(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-KEM-512",
                 "tests": [{"tcId": 1, "d": "AA", "z": "AB" * 32}]}
        with self.assertRaises(ValueError):
            build_mlkem_response(request("keyGen", "FIPS203", group), FakeKem())

    def test_fails_closed_on_nonhex_input(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-KEM-512",
                 "tests": [{"tcId": 1, "d": "GG" * 32, "z": "AB" * 32}]}
        with self.assertRaises(ValueError):
            build_mlkem_response(request("keyGen", "FIPS203", group), FakeKem())

    def test_multi_group_keygen_aft_preserves_ids_and_sizes(self):
        """ACVP keyGen may deliver every parameter set in one vector set."""
        groups = []
        for index, name in enumerate(PARAMETERS, 1):
            groups.append({"tgId": index, "testType": "AFT",
                           "parameterSet": name,
                           "tests": [{"tcId": index * 10, "d": "AB" * 32,
                                      "z": "CD" * 32},
                                     {"tcId": index * 10 + 1, "d": "CD" * 32,
                                      "z": "AB" * 32}]})
        envelope = request("keyGen", "FIPS203", groups[0])
        envelope[1]["testGroups"] = groups
        response = build_mlkem_response(envelope, FakeKem())[1]["testGroups"]
        self.assertEqual([item["tgId"] for item in response], [1, 2, 3])
        for original, answer in zip(groups, response):
            name = original["parameterSet"]
            self.assertEqual([item["tcId"] for item in answer["tests"]],
                             [item["tcId"] for item in original["tests"]])
            for case in answer["tests"]:
                self.assertEqual(len(case["ek"]), 2 * PARAMETERS[name][1])
                self.assertEqual(len(case["dk"]), 2 * PARAMETERS[name][2])

    def test_multi_group_kem_aft_val_and_response_fields(self):
        """FIPS203-tr1 expanded-key AFT/VAL groups share an ACVP vector set."""
        name = "ML-KEM-1024"
        pklen, sklen, ctlen = PARAMETERS[name][1:]
        group_aft = {"tgId": 1, "testType": "AFT", "parameterSet": name,
                     "function": "encapsulation",
                     "tests": [{"tcId": 20, "ek": "AA" * pklen, "m": "BB" * 32}]}
        group_val = {"tgId": 2, "testType": "VAL", "parameterSet": name,
                     "function": "decapsulation", "keyFormat": "expanded",
                     "tests": [{"tcId": 21, "dk": "CC" * sklen,
                                "c": "DD" * ctlen}]}
        envelope = request("encapDecap", "FIPS203-tr1", group_aft)
        envelope[1]["testGroups"] = [group_aft, group_val]
        groups = build_mlkem_response(envelope, FakeKem())[1]["testGroups"]
        self.assertEqual(groups[0]["tests"][0],
                         {"tcId": 20, "c": "03" * ctlen, "k": "04" * 32})
        self.assertEqual(groups[1]["tests"][0], {"tcId": 21, "k": "05" * 32})

    def test_rejects_unadvertised_kem_functions_and_key_formats(self):
        """Never silently accept key checks or a seed-only private key."""
        for name in PARAMETERS:
            for function, key_format in (
                    ("encapsulationKeyCheck", None),
                    ("decapsulationKeyCheck", "expanded"),
                    ("decapsulation", "seed")):
                group = {"tgId": 3, "testType": "VAL",
                         "parameterSet": name, "function": function,
                         "tests": [{"tcId": 55}]}
                if key_format is not None:
                    group["keyFormat"] = key_format
                with self.subTest(parameter=name, function=function,
                                  format=key_format), self.assertRaises(ValueError):
                    build_mlkem_response(
                        request("encapDecap", "FIPS203-tr1", group), FakeKem())

    def test_registration_requires_every_hash_prerequisite(self):
        """All four NIST SHA3/SHAKE primitives must be registered together."""
        required = ("SHA3-256", "SHA3-512", "SHAKE-128", "SHAKE-256")
        for missing in required:
            selected = tuple(item for item in required if item != missing) + ("ML-KEM",)
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                registration(selected)

    def test_global_vector_dispatch(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-KEM-512",
                 "tests": [{"tcId": 1, "d": "AB" * 32, "z": "CD" * 32}]}
        self.assertEqual(build_response(request("keyGen", "FIPS203", group), FakeQsc())[1]["vsId"], 101)

    def test_global_vector_dispatch_without_library(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-KEM-512", "tests": []}
        with self.assertRaises(ValueError):
            build_response(request("keyGen", "FIPS203", group), object())


if __name__ == "__main__":
    unittest.main()
