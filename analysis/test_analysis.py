# analysis/test_analysis.py
#
# Run from project root:
#   python -m unittest analysis.test_analysis -v

import time
import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analysis.capabilities import ALGORITHMS
from analysis import timing, brute_force


class TestCapabilities(unittest.TestCase):

    def test_all_algorithms_have_required_fields(self):
        # Input:  ALGORITHMS list
        # Output: every entry has the required keys
        required = {'name', 'can_encrypt', 'can_decrypt', 'note', 'setup', 'encrypt', 'decrypt'}
        for algo in ALGORITHMS:
            with self.subTest(algo=algo['name']):
                for field in required:
                    self.assertIn(field, algo)

    def test_six_algorithms_registered(self):
        self.assertEqual(len(ALGORITHMS), 6)

    def test_ecc_is_non_cipher(self):
        # ECC only does ECDH — no message encrypt/decrypt
        ecc = next(a for a in ALGORITHMS if 'ECC' in a['name'])
        self.assertFalse(ecc['can_encrypt'])
        self.assertFalse(ecc['can_decrypt'])
        self.assertIsNone(ecc['setup'])

    def test_five_algorithms_support_encrypt_and_decrypt(self):
        cipher_algos = [a for a in ALGORITHMS if a['can_encrypt']]
        self.assertEqual(len(cipher_algos), 5)


class TestTimingAnalysis(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Run once — RSA key generation is slow
        cls.results = timing.run_timing_analysis("HELLO")

    def test_returns_one_result_per_algorithm(self):
        # Input:  "HELLO"
        # Output: one result dict per algorithm
        self.assertEqual(len(self.results), len(ALGORITHMS))

    def test_ecc_has_no_timing(self):
        ecc = next(r for r in self.results if 'ECC' in r['name'])
        self.assertIsNone(ecc['enc_ms'])
        self.assertIsNone(ecc['dec_ms'])
        self.assertIsNone(ecc['roundtrip_ok'])

    def test_substitution_roundtrip(self):
        r = next(r for r in self.results if r['name'] == 'Substitution')
        self.assertIsNone(r['error'], msg=f"Unexpected error: {r['error']}")
        self.assertTrue(r['roundtrip_ok'])

    def test_des_roundtrip(self):
        r = next(r for r in self.results if 'DES' in r['name'])
        self.assertIsNone(r['error'], msg=f"Unexpected error: {r['error']}")
        self.assertTrue(r['roundtrip_ok'])

    def test_aes_roundtrip(self):
        r = next(r for r in self.results if r['name'] == 'AES-128')
        self.assertIsNone(r['error'], msg=f"Unexpected error: {r['error']}")
        self.assertTrue(r['roundtrip_ok'])

    def test_rsa_roundtrip(self):
        r = next(r for r in self.results if 'RSA' in r['name'])
        self.assertIsNone(r['error'], msg=f"Unexpected error: {r['error']}")
        self.assertTrue(r['roundtrip_ok'])

    def test_enc_ms_is_measured_for_cipher_algorithms(self):
        # enc_ms must be a non-negative number (0.0 is valid on fast clocks)
        for r in self.results:
            if r['can_encrypt'] and r['error'] is None:
                with self.subTest(name=r['name']):
                    self.assertIsNotNone(r['enc_ms'])
                    self.assertGreaterEqual(r['enc_ms'], 0)


class TestBruteForce(unittest.TestCase):

    def test_returns_one_result_per_algorithm(self):
        # Input:  short ciphertext, short timeout
        # Output: one result dict per algorithm
        results = brute_force.run_brute_force("HELLO", timeout_seconds=5)
        self.assertEqual(len(results), len(ALGORITHMS))

    def test_substitution_is_attempted(self):
        results = brute_force.run_brute_force("ITSSG", timeout_seconds=5)
        sub = next(r for r in results if r['algorithm'] == 'Substitution')
        self.assertTrue(sub['attempted'])
        self.assertIsNotNone(sub['elapsed_ms'])

    def test_double_transposition_is_attempted(self):
        results = brute_force.run_brute_force("HELLOWORLD", timeout_seconds=5)
        dt = next(r for r in results if r['algorithm'] == 'Double Transposition')
        self.assertTrue(dt['attempted'])

    def test_des_aes_rsa_ecc_are_skipped(self):
        results = brute_force.run_brute_force("DEADBEEF", timeout_seconds=5)
        skipped = ['DES (Simplified)', 'AES-128', 'RSA-512', 'ECC (ECDH)']
        for r in results:
            if r['algorithm'] in skipped:
                with self.subTest(algo=r['algorithm']):
                    self.assertFalse(r['attempted'])

    def test_timeout_respected(self):
        # Input:  2-second timeout
        # Output: total elapsed wall time stays well under 5 seconds
        t0 = time.monotonic()
        brute_force.run_brute_force("XYZABC", timeout_seconds=2)
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 5)

    def test_result_has_required_fields(self):
        results = brute_force.run_brute_force("HELLO", timeout_seconds=2)
        required = {'algorithm', 'attempted', 'elapsed_ms', 'found', 'guess', 'note'}
        for r in results:
            with self.subTest(algo=r['algorithm']):
                for field in required:
                    self.assertIn(field, r)


if __name__ == '__main__':
    unittest.main(verbosity=2)
