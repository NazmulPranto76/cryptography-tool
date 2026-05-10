# ciphers/rsa/test_rsa.py
#
# Unit Tests for RSA.
#
# Run from project root:
#   python -m unittest ciphers.rsa.test_rsa -v

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from ciphers.rsa import cipher as rsa_cipher


class TestMillerRabin(unittest.TestCase):
    """Tests for the Miller-Rabin primality test."""

    def test_known_primes(self):
        """Well-known prime numbers must return True."""
        known_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 97, 101, 65537]
        for p in known_primes:
            with self.subTest(p=p):
                self.assertTrue(rsa_cipher._miller_rabin(p))

    def test_known_composites(self):
        """Non-prime numbers must return False."""
        known_composites = [4, 6, 8, 9, 10, 15, 100, 1000, 65536]
        for n in known_composites:
            with self.subTest(n=n):
                self.assertFalse(rsa_cipher._miller_rabin(n))

    def test_small_edge_cases(self):
        """Edge cases: 0 and 1 are not prime."""
        self.assertFalse(rsa_cipher._miller_rabin(0))
        self.assertFalse(rsa_cipher._miller_rabin(1))


class TestKeyGeneration(unittest.TestCase):
    """Tests for RSA key generation."""

    @classmethod
    def setUpClass(cls):
        """
        setUpClass runs ONCE before all tests in this class.
        We generate keys once and share them — key generation is slow!
        """
        cls.keys = rsa_cipher.generate_keys(bits=64)  # 128-bit key for speed

    def test_keys_dict_has_all_fields(self):
        """generate_keys() must return a dict with all required fields."""
        required = ['e', 'd', 'n', 'p', 'q', 'phi', 'key_bits']
        for field in required:
            with self.subTest(field=field):
                self.assertIn(field, self.keys)

    def test_n_equals_p_times_q(self):
        """n must equal p * q."""
        self.assertEqual(self.keys['n'], self.keys['p'] * self.keys['q'])

    def test_phi_equals_p_minus_1_times_q_minus_1(self):
        """phi must equal (p-1) * (q-1)."""
        expected_phi = (self.keys['p'] - 1) * (self.keys['q'] - 1)
        self.assertEqual(self.keys['phi'], expected_phi)

    def test_e_and_phi_are_coprime(self):
        """gcd(e, phi) must equal 1 for the key to be valid."""
        import math
        self.assertEqual(math.gcd(self.keys['e'], self.keys['phi']), 1)

    def test_e_times_d_mod_phi_equals_1(self):
        """e * d mod phi must equal 1 (fundamental RSA property)."""
        check = (self.keys['e'] * self.keys['d']) % self.keys['phi']
        self.assertEqual(check, 1)

    def test_p_and_q_are_prime(self):
        """p and q must be prime numbers."""
        self.assertTrue(rsa_cipher._miller_rabin(self.keys['p']))
        self.assertTrue(rsa_cipher._miller_rabin(self.keys['q']))


class TestEncryptDecrypt(unittest.TestCase):
    """Tests for RSA encrypt and decrypt."""

    @classmethod
    def setUpClass(cls):
        """Generate keys once for all encrypt/decrypt tests."""
        cls.keys = rsa_cipher.generate_keys(bits=64)

    def test_roundtrip_short_message(self):
        """Encrypt then decrypt a short string — must recover original."""
        message = "Hi"
        result = rsa_cipher.encrypt(message, self.keys['e'], self.keys['n'])
        pt = rsa_cipher.decrypt(result['chunks'], self.keys['d'], self.keys['n'])
        self.assertEqual(pt, message)

    def test_roundtrip_single_char(self):
        """Single character must roundtrip correctly."""
        message = "A"
        result = rsa_cipher.encrypt(message, self.keys['e'], self.keys['n'])
        pt = rsa_cipher.decrypt(result['chunks'], self.keys['d'], self.keys['n'])
        self.assertEqual(pt, message)

    def test_roundtrip_long_message(self):
        """A message longer than one RSA chunk must roundtrip correctly (multi-chunk)."""
        message = "Hello RSA! This is a longer message to test chunked encryption."
        result = rsa_cipher.encrypt(message, self.keys['e'], self.keys['n'])
        pt = rsa_cipher.decrypt(result['chunks'], self.keys['d'], self.keys['n'])
        self.assertEqual(pt, message)

    def test_encrypt_returns_dict_with_required_keys(self):
        """encrypt() must return a dict with 'chunks', 'num_chunks', 'chunk_size_bytes'."""
        result = rsa_cipher.encrypt("X", self.keys['e'], self.keys['n'])
        self.assertIn('chunks', result)
        self.assertIn('num_chunks', result)
        self.assertIn('chunk_size_bytes', result)

    def test_encrypt_chunks_are_integers(self):
        """Every chunk in the ciphertext list must be an integer."""
        result = rsa_cipher.encrypt("Hello", self.keys['e'], self.keys['n'])
        for chunk in result['chunks']:
            self.assertIsInstance(chunk, int)

    def test_ciphertext_differs_from_plaintext(self):
        """Ciphertext integer must differ from the plaintext integer."""
        message = "A"
        result = rsa_cipher.encrypt(message, self.keys['e'], self.keys['n'])
        from utils.bit_helpers import bytes_to_int
        m_int = bytes_to_int(message.encode('utf-8'))
        self.assertNotEqual(result['chunks'][0], m_int)


class TestFactorizationAttack(unittest.TestCase):
    """Tests for the Pollard's Rho factorization attack."""

    def test_attack_succeeds_on_small_key(self):
        """
        The factorization attack must successfully find p and q for a small key.
        We generate a fresh tiny key and try to factor it.
        """
        # Generate a tiny key (16-bit primes = ~32-bit modulus)
        tiny_keys = rsa_cipher.generate_keys(bits=16)
        result = rsa_cipher.factorization_attack(tiny_keys['n'], tiny_keys['e'], max_attempts=50)

        self.assertTrue(result['success'], "Attack should succeed on a 32-bit modulus.")
        # The two recovered factors must multiply to n
        self.assertEqual(result['p'] * result['q'], tiny_keys['n'])

    def test_attack_result_contains_required_fields(self):
        """The result dict must have all required fields."""
        tiny_keys = rsa_cipher.generate_keys(bits=16)
        result = rsa_cipher.factorization_attack(tiny_keys['n'], tiny_keys['e'])
        for field in ['success', 'p', 'q', 'd_recovered', 'attempts', 'note']:
            with self.subTest(field=field):
                self.assertIn(field, result)


if __name__ == '__main__':
    unittest.main(verbosity=2)
