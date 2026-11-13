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

"""Strict AES ACVP JSON adapter tests; independent native checks are in test_aes_native.py."""

import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aes_client import build_aes_response, build_ecb_response
import demo_client


class StubAes:
    """Deterministic test double, independent of the QSC shared library."""

    def transform(self, key, iv, aad, payload, tag=None):
        if tag is not None and tag[0] != 0xAA:
            return False, b'', b''
        return True, payload if tag is not None else b'\x44' * len(payload), b'\xAA' * 16

    def ecb(self, key, block, encryption):
        return bytes(x ^ 0x55 for x in block)


class AesVectorTests(unittest.TestCase):
    def gcm(self, direction='encrypt'):
        return [{'acvVersion': '1.0'}, {'vsId': 15, 'algorithm': 'ACVP-AES-GCM',
                'testGroups': [{'tgId': 3, 'testType': 'AFT', 'direction': direction,
                                'keyLen': 128, 'ivLen': 96, 'ivGen': 'external',
                                'tagLen': 128, 'payloadLen': 16, 'aadLen': 8,
                                'tests': [{'tcId': 4, 'key': '00' * 16,
                                           'iv': '01' * 12, 'aad': '02',
                                           'pt' if direction == 'encrypt' else 'ct': '1234',
                                           'tag': 'AA' * 16}]}]}]

    def test_aes_gcm_encrypt_response(self):
        result = build_aes_response(self.gcm(), StubAes())
        self.assertEqual(result[1]['testGroups'][0]['tests'][0],
                         {'tcId': 4, 'iv': '01' * 12, 'ct': '4444', 'tag': 'AA' * 16})

    def test_aes_gcm_decrypt_and_reject(self):
        envelope = self.gcm('decrypt')
        self.assertEqual(build_aes_response(envelope, StubAes())[1]['testGroups'][0]['tests'][0],
                         {'tcId': 4, 'pt': '1234'})
        envelope[1]['testGroups'][0]['tests'][0]['tag'] = '01' * 16
        self.assertEqual(build_aes_response(envelope, StubAes())[1]['testGroups'][0]['tests'][0],
                         {'tcId': 4, 'testPassed': False})

    def test_aes_gcm_rejects_wrong_tag_size(self):
        envelope = self.gcm()
        envelope[1]['testGroups'][0]['tagLen'] = 96
        with self.assertRaises(ValueError):
            build_aes_response(envelope, StubAes())

    def test_aes_gcm_rejects_unsupported_group(self):
        envelope = self.gcm()
        envelope[1]['testGroups'][0]['testType'] = 'MCT'
        with self.assertRaises(ValueError):
            build_aes_response(envelope, StubAes())

    def test_aes_gcm_rejects_truncated_or_missing_inputs(self):
        envelope = self.gcm()
        del envelope[1]['testGroups'][0]['tests'][0]['key']
        with self.assertRaises(ValueError):
            build_aes_response(envelope, StubAes())

    def test_aes_gcm_nist_group_empty_payload_and_aad(self):
        """AFT group lengths may be zero, with empty hex-valued test inputs."""
        for keylen in (128, 256):
            for direction in ('encrypt', 'decrypt'):
                envelope = self.gcm(direction)
                group = envelope[1]['testGroups'][0]
                group['keyLen'] = keylen
                group['payloadLen'] = 0
                group['aadLen'] = 0
                group['ivGenMode'] = '8.2.2'
                case = group['tests'][0]
                case['key'] = '00' * (keylen // 8)
                case['aad'] = ''
                case['pt' if direction == 'encrypt' else 'ct'] = ''
                result = build_aes_response(envelope, StubAes())
                actual = result[1]['testGroups'][0]['tests'][0]
                if direction == 'encrypt':
                    self.assertEqual(actual, {'tcId': 4, 'iv': '01' * 12,
                                              'ct': '', 'tag': 'AA' * 16})
                else:
                    self.assertEqual(actual, {'tcId': 4, 'pt': ''})

    def test_aes_gcm_nist_legacy_field_names(self):
        """ACVP request aliases plainText and cipherText must both work."""
        for direction, source_name in (('encrypt', 'plainText'),
                                       ('decrypt', 'cipherText')):
            envelope = self.gcm(direction)
            case = envelope[1]['testGroups'][0]['tests'][0]
            case[source_name] = case.pop('pt' if direction == 'encrypt' else 'ct')
            actual = build_aes_response(envelope, StubAes())[1]['testGroups'][0]['tests'][0]
            self.assertEqual(actual['tcId'], 4)
            self.assertEqual(actual['ct' if direction == 'encrypt' else 'pt'],
                             '4444' if direction == 'encrypt' else '1234')

    def test_aes_gcm_nist_multiple_group_lengths(self):
        """GCM AFT uses bit lengths at group scope for payload and AAD."""
        for data_len, aad_len in ((0, 0), (1, 1), (16, 0),
                                  (17, 16), (32, 32), (8192, 8)):
            envelope = self.gcm()
            group = envelope[1]['testGroups'][0]
            group['payloadLen'] = data_len * 8
            group['aadLen'] = aad_len * 8
            case = group['tests'][0]
            case['pt'] = '01' * data_len
            case['aad'] = '02' * aad_len
            result = build_aes_response(envelope, StubAes())
            self.assertEqual(result[1]['testGroups'][0]['tests'][0]['ct'],
                             '44' * data_len)

    def test_aes_gcm_reject_mismatched_length_metadata(self):
        """Invalid group payload or AAD length must fail before native AES."""
        for field, actual in (('payloadLen', 8), ('aadLen', 16)):
            envelope = self.gcm()
            envelope[1]['testGroups'][0][field] = actual
            with self.subTest(field=field), self.assertRaisesRegex(ValueError,
                                                                    'does not match'):
                build_aes_response(envelope, StubAes())

    def test_aes_gcm_decrypt_invalid_tag_reports_failure(self):
        """Authentication rejection is a valid ACVP response, not a client error."""
        envelope = self.gcm('decrypt')
        case = envelope[1]['testGroups'][0]['tests'][0]
        case['tag'] = '00' * 16
        result = build_aes_response(envelope, StubAes())
        self.assertEqual(result[1]['testGroups'][0]['tests'][0],
                         {'tcId': 4, 'testPassed': False})

    def test_aes_ecb_aft(self):
        envelope = [{'acvVersion': '1.0'}, {'vsId': 99, 'algorithm': 'ACVP-AES-ECB',
                    'testGroups': [{'tgId': 3, 'direction': 'encrypt', 'testType': 'AFT',
                                    'keyLen': 128,
                                    'tests': [{'tcId': 10, 'key': '11' * 16,
                                               'plainText': '00' * 16}]}]}]
        result = build_ecb_response(envelope, StubAes())
        self.assertEqual(result[1]['testGroups'][0]['tests'][0],
                         {'tcId': 10, 'ct': '55' * 16})

    def test_aes_ecb_aft_multiblock_encrypt_decrypt(self):
        """ECB AFT transforms each complete block without changing its order."""
        plaintext = bytes(range(48))
        encrypted = bytes(value ^ 0x55 for value in plaintext)
        for direction, source, expected in (
                ("encrypt", plaintext, encrypted),
                ("decrypt", encrypted, plaintext)):
            field = "pt" if direction == "encrypt" else "ct"
            result_field = "ct" if direction == "encrypt" else "pt"
            envelope = [{'acvVersion': '1.0'},
                        {'vsId': 99, 'algorithm': 'ACVP-AES-ECB',
                         'testGroups': [{'tgId': 3, 'testType': 'AFT',
                                         'direction': direction, 'keyLen': 128,
                                         'tests': [{'tcId': 10, 'key': '11' * 16,
                                                    field: source.hex()}]}]}]
            result = build_ecb_response(envelope, StubAes())
            self.assertEqual(result[1]['testGroups'][0]['tests'][0],
                             {'tcId': 10, result_field: expected.hex().upper()})

    def test_aes_ecb_reject_non_aligned_and_oversized_aft(self):
        """ECB AFT must reject partial, empty and unbounded payloads."""
        for size in (0, 15, 17, 8193, 8208):
            envelope = [{'acvVersion': '1.0'},
                        {'vsId': 99, 'algorithm': 'ACVP-AES-ECB',
                         'testGroups': [{'tgId': 3, 'testType': 'AFT',
                                         'direction': 'encrypt', 'keyLen': 128,
                                         'tests': [{'tcId': 10, 'key': '11' * 16,
                                                    'pt': '00' * size}]}]}]
            with self.subTest(size=size), self.assertRaises(ValueError):
                build_ecb_response(envelope, StubAes())

    def test_aes_ecb_mct_reject_multiblock_seed(self):
        """ECB Monte Carlo requires one 128-bit seed input."""
        envelope = [{'acvVersion': '1.0'},
                    {'vsId': 99, 'algorithm': 'ACVP-AES-ECB',
                     'testGroups': [{'tgId': 3, 'direction': 'encrypt', 'testType': 'MCT',
                                     'keyLen': 128,
                                     'tests': [{'tcId': 10, 'key': '11' * 16,
                                                'pt': '00' * 32}]}]}]
        with self.assertRaisesRegex(ValueError, "MCT input must be one block"):
            build_ecb_response(envelope, StubAes())

    def test_aes_ecb_mct_response_shape(self):
        envelope = [{'acvVersion': '1.0'}, {'vsId': 99, 'algorithm': 'ACVP-AES-ECB',
                    'testGroups': [{'tgId': 3, 'direction': 'decrypt', 'testType': 'MCT',
                                    'keyLen': 256,
                                    'tests': [{'tcId': 10, 'key': '11' * 32,
                                               'ct': '00' * 16}]}]}]
        result = build_ecb_response(envelope, StubAes())
        records = result[1]['testGroups'][0]['tests'][0]['resultsArray']
        self.assertEqual(len(records), 100)
        self.assertEqual(records[0]['key'], '11' * 32)
        self.assertEqual(records[0]['pt'], '00' * 16)

    def test_aes_registration_and_prerequisite(self):
        selected = ('ACVP-AES-ECB', 'ACVP-AES-GCM')
        r = demo_client.registration(selected)[1]['algorithms']
        self.assertEqual([entry['algorithm'] for entry in r], list(selected))
        self.assertEqual(r[1]['tagLen'], [128])
        self.assertEqual(r[1]['prereqVals'][0]['valValue'], 'same')
        with self.assertRaises(ValueError):
            demo_client.registration(('ACVP-AES-GCM',))


if __name__ == '__main__':
    unittest.main()

class DemoAesTransportTests(unittest.TestCase):
    """Prove both AES vector sets execute consecutively through the Demo controller."""

    def test_consecutive_aes_demo_protocol_path(self):
        class Server:
            def __init__(self):
                self.submitted = []
                self.session = '/acvp/v1/testSessions/121'

            def request(self, method, path, token=None, body=None):
                if path.endswith('/login'):
                    return [{'acvVersion': '1.0'}, {'accessToken': 'never-print-this'}]
                if method == 'POST' and path.endswith('/testSessions'):
                    return [{'acvVersion': '1.0'}, {'url': self.session,
                            'vectorSetUrls': [self.session + '/vectorSets/1',
                                              self.session + '/vectorSets/2']}]
                if method == 'GET' and path.endswith('vectorSets/1'):
                    return [{'acvVersion': '1.0'}, {'vsId': 1, 'algorithm': 'ACVP-AES-ECB',
                            'testGroups': [{'tgId': 1, 'testType': 'AFT',
                                            'direction': 'encrypt', 'keyLen': 128,
                                            'tests': [{'tcId': 1, 'key': '00' * 16,
                                                       'pt': '11' * 16}]}]}]
                if method == 'GET' and path.endswith('vectorSets/2'):
                    value = AesVectorTests().gcm()
                    value[1]["vsId"] = 2
                    return value
                if method == 'POST' and path.endswith('/results'):
                    self.submitted.append(body[1]['vsId'])
                    return [{'acvVersion': '1.0'}, {'status': 'received'}]
                if method == 'GET' and path.endswith('/results'):
                    return [{'acvVersion': '1.0'}, {'passed': True, 'results': [
                            {'status': 'passed', 'vectorSetUrl': self.session + '/vectorSets/1'},
                            {'status': 'passed', 'vectorSetUrl': self.session + '/vectorSets/2'}]}]
                raise AssertionError((method, path))

        class Qsc:
            aes = StubAes()

        server = Server()
        result = demo_client.execute(server, Qsc(),
                                     'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
                                     ('ACVP-AES-ECB', 'ACVP-AES-GCM'),
                                     poll_count=1)
        self.assertEqual(result['status'], 'PASS_DEMO_SAMPLE')
        self.assertEqual(server.submitted, [1, 2])
        self.assertNotIn('never-print-this', repr(result))
