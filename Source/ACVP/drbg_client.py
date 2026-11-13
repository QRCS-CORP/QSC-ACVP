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

"""Deterministic native HCG/CSG adapters for ACVP vector qualification.

Only HCG is registered with SP800-90Ar1. CSG remains a research candidate.
Neither class acquires entropy; the caller supplies every seed and reseed.
"""

import ctypes
from pathlib import Path


def _buffer(value: bytes):
    if not isinstance(value, bytes):
        raise ValueError("DRBG input must be bytes")
    return ctypes.create_string_buffer(value) if value else None


class QscDrbg:
    """Bind a pinned native QSC DRBG library without relying on compiler struct layout."""

    def __init__(self, library: Path, mechanism: str = "hcg"):
        if mechanism not in ("hcg", "csg"):
            raise ValueError("Unsupported QSC DRBG mechanism")
        self.mechanism = mechanism
        self.dll = ctypes.CDLL(str(library.resolve()))
        size = getattr(self.dll, f"qsc_acvp_{mechanism}_state_size")
        size.argtypes = []
        size.restype = ctypes.c_size_t
        state_bytes = size()
        if not 32 <= state_bytes <= 4096:
            raise ValueError("Invalid native QSC DRBG state size")
        self._state = (ctypes.c_uint64 * ((state_bytes + 7) // 8))()
        self._instantiate = getattr(self.dll, f"qsc_{mechanism}_instantiate")
        self._reseed = getattr(self.dll, f"qsc_{mechanism}_reseed")
        self._generate = getattr(self.dll, f"qsc_{mechanism}_generate_ex")
        self._dispose = getattr(self.dll, f"qsc_{mechanism}_dispose")
        self._dispose.argtypes = [ctypes.c_void_p]
        self._dispose.restype = None
        if mechanism == "hcg":
            self._instantiate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                          ctypes.c_void_p, ctypes.c_size_t,
                                          ctypes.c_void_p, ctypes.c_size_t]
        else:
            self._instantiate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                          ctypes.c_void_p, ctypes.c_size_t]
        self._instantiate.restype = ctypes.c_bool
        self._reseed.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                 ctypes.c_void_p, ctypes.c_size_t]
        self._reseed.restype = ctypes.c_bool
        self._generate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_void_p, ctypes.c_size_t]
        self._generate.restype = ctypes.c_bool
        self._active = False

    def instantiate(self, entropy: bytes, nonce: bytes = b"", personalization: bytes = b""):
        self.dispose()
        if self.mechanism == "hcg":
            ok = self._instantiate(self._state, _buffer(entropy), len(entropy),
                                   _buffer(nonce), len(nonce),
                                   _buffer(personalization), len(personalization))
        else:
            if nonce:
                raise ValueError("CSG XDRBG instantiate has no separate nonce")
            ok = self._instantiate(self._state, _buffer(entropy), len(entropy),
                                   _buffer(personalization), len(personalization))
        if not ok:
            raise ValueError("Native DRBG instantiate failed")
        self._active = True

    def reseed(self, entropy: bytes, additional: bytes = b""):
        if not self._active or not self._reseed(self._state, _buffer(entropy), len(entropy),
                                                _buffer(additional), len(additional)):
            raise ValueError("Native DRBG reseed failed")

    def generate(self, length: int, additional: bytes = b"") -> bytes:
        if (not self._active or type(length) is not int or length < 1 or
                length > (65536 if self.mechanism == "hcg" else 344)):
            raise ValueError("Invalid native DRBG generate request")
        result = ctypes.create_string_buffer(length)
        if not self._generate(self._state, result, length,
                              _buffer(additional), len(additional)):
            raise ValueError("Native DRBG generate failed")
        return result.raw

    def dispose(self):
        self._dispose(self._state)
        self._active = False


ALGORITHM = "hmacDRBG"
REVISION = "SP800-90Ar1"


def registration() -> dict:
    """Advertise strictly the deterministic SHA2-512 HMAC_DRBG profile tested."""
    return {
        "algorithm": ALGORITHM, "revision": REVISION,
        "prereqVals": [{"algorithm": "HMAC", "valValue": "same"}],
        "predResistanceEnabled": [False],
        "reseedImplemented": True,
        "capabilities": [{
            "mode": "SHA2-512",
            "entropyInputLen": [256],
            "nonceLen": [128],
            "persoStringLen": [0, 256],
            "additionalInputLen": [0, 256],
            "returnedBitsLen": [512]
        }]
    }


def _hex(value, length, field):
    if not isinstance(value, str) or len(value) != length * 2:
        raise ValueError(f"Invalid DRBG {field} length")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"Invalid DRBG {field} encoding") from exc


def build_response(envelope: list, native: QscDrbg) -> list:
    """Execute all ACVP HMAC_DRBG operations in sequence, retaining the last generate."""
    if (not isinstance(envelope, list) or len(envelope) != 2 or
            envelope[0] != {"acvVersion": "1.0"} or not isinstance(envelope[1], dict)):
        raise ValueError("Invalid DRBG ACVP envelope")
    vector = envelope[1]
    if (vector.get("algorithm") != ALGORITHM or vector.get("revision") != REVISION or
            type(vector.get("vsId")) is not int or not isinstance(vector.get("testGroups"), list)):
        raise ValueError("Unsupported DRBG ACVP vector set")
    output_groups = []
    for group in vector["testGroups"]:
        if (not isinstance(group, dict) or type(group.get("tgId")) is not int or
                group.get("testType") != "AFT" or group.get("mode") != "SHA2-512" or
                type(group.get("predResistance")) is not bool or
                group["predResistance"] or type(group.get("reSeed")) is not bool or
                group.get("entropyInputLen") != 256 or group.get("nonceLen") != 128 or
                group.get("persoStringLen") not in (0, 256) or
                group.get("additionalInputLen") not in (0, 256) or
                group.get("returnedBitsLen") != 512 or not isinstance(group.get("tests"), list)):
            raise ValueError("Unsupported DRBG ACVP group")
        tests = []
        for case in group["tests"]:
            if (not isinstance(case, dict) or type(case.get("tcId")) is not int or
                    not isinstance(case.get("otherInput"), list) or
                    len(case["otherInput"]) < 2 or len(case["otherInput"]) > 8):
                raise ValueError("Malformed DRBG ACVP case")
            entropy = _hex(case.get("entropyInput"), 32, "entropyInput")
            nonce = _hex(case.get("nonce"), 16, "nonce")
            perso = _hex(case.get("persoString"), group["persoStringLen"] // 8, "persoString")
            native.instantiate(entropy, nonce, perso)
            last = None
            saw_reseed = False
            generated = 0
            try:
                for op in case["otherInput"]:
                    if not isinstance(op, dict):
                        raise ValueError("Invalid DRBG otherInput record")
                    purpose = op.get("intendedUse")
                    additional = _hex(op.get("additionalInput"),
                                      group["additionalInputLen"] // 8, "additionalInput")
                    if purpose == "reSeed":
                        if not group["reSeed"] or saw_reseed or generated:
                            raise ValueError("Invalid DRBG explicit reseed sequence")
                        entropy = _hex(op.get("entropyInput"), 32, "reseed entropy")
                        native.reseed(entropy, additional)
                        saw_reseed = True
                    elif purpose == "generate":
                        if op.get("entropyInput", "") != "":
                            raise ValueError("Unexpected entropy on non-PR DRBG generate")
                        last = native.generate(64, additional)
                        generated += 1
                    else:
                        raise ValueError("Unsupported DRBG intendedUse")
                if generated != 2 or saw_reseed != group["reSeed"] or last is None:
                    raise ValueError("Incomplete DRBG ACVP generate/reseed sequence")
                tests.append({"tcId": case["tcId"], "returnedBits": last.hex().upper()})
            finally:
                native.dispose()
        output_groups.append({"tgId": group["tgId"], "tests": tests})
    return [{"acvVersion": "1.0"}, {"vsId": vector["vsId"], "testGroups": output_groups}]
