# ciphers/des/test_des.py
#
# Unit Tests for the Real DES Cipher Implementation.
# This covers key generation, key scheduling, block encryption/decryption,
# and the full encrypt/decrypt roundtrip for any-length plaintext.
#
# Run from project root:
#   python -m unittest ciphers.des.test_des -v

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from ciphers.des import cipher as des_cipher
from utils.bit_helpers import bytes_to_bits, bits_to_bytes


class TestDESKeyGeneration(unittest.TestCase):
    """Tests for generate_key() — the random key generator."""

    def test_key_is_8_bytes(self):
        """Generated key must be exactly 8 bytes (64 bits)."""
        key = des_cipher.generate_key()
        self.assertEqual(len(key), 8)

    def test_key_is_bytes_type(self):
        """Key must be a bytes object, not a string or list."""
        key = des_cipher.generate_key()
        self.assertIsInstance(key, bytes)


class TestDESKeySchedule(unittest.TestCase):
    """Tests for generate_round_keys() — the DES key schedule."""

    def test_round_keys_count(self):
        """Real DES must produce exactly 16 round keys (one per round)."""
        key = des_cipher.generate_key()
        round_keys = des_cipher.generate_round_keys(key)
        self.assertEqual(len(round_keys), 16)

    def test_each_round_key_is_48_bits(self):
        """Each round key must be exactly 48 bits (list of 0s and 1s)."""
        key = des_cipher.generate_key()
        round_keys = des_cipher.generate_round_keys(key)
        for i, rk in enumerate(round_keys):
            with self.subTest(round=i + 1):
                self.assertEqual(len(rk), 48)
                self.assertTrue(all(b in (0, 1) for b in rk))

    def test_round_keys_are_different(self):
        """The 16 round keys must not all be identical — the schedule must mix them."""
        key = bytes([0b10101010] * 8)
        round_keys = des_cipher.generate_round_keys(key)
        unique_keys = set(tuple(rk) for rk in round_keys)
        self.assertGreater(len(unique_keys), 1)

    def test_invalid_key_length_raises(self):
        """generate_round_keys() must raise ValueError for keys that aren't 8 bytes."""
        with self.assertRaises(ValueError):
            des_cipher.generate_round_keys(b'SHORT')


class TestDESEncryptDecrypt(unittest.TestCase):
    """Tests for the public encrypt() and decrypt() functions."""

    def setUp(self):
        """Use a fixed key so tests are reproducible."""
        self.key = bytes(range(8))   # 0x00 01 02 03 04 05 06 07

    def test_encrypt_returns_required_keys(self):
        """encrypt() must return a dict with the expected fields."""
        result = des_cipher.encrypt("HELLO", self.key)
        self.assertIn('ciphertext_hex', result)
        self.assertIn('round_keys', result)
        self.assertIn('num_blocks', result)
        self.assertIn('plaintext_padded_hex', result)

    def test_encrypt_returns_16_round_keys(self):
        """The 'round_keys' field in the encrypt result must contain all 16 keys."""
        result = des_cipher.encrypt("TEST", self.key)
        self.assertEqual(len(result['round_keys']), 16)

    def test_ciphertext_length_is_multiple_of_16_hex(self):
        """Ciphertext hex must be a multiple of 16 chars (8 bytes per block × 2 hex per byte)."""
        result = des_cipher.encrypt("HELLO WORLD THIS IS A LONG MESSAGE", self.key)
        self.assertEqual(len(result['ciphertext_hex']) % 16, 0)

    def test_roundtrip_simple(self):
        """Encrypt then decrypt must recover the original plaintext exactly."""
        plaintext = "ABCDEFGH"
        enc = des_cipher.encrypt(plaintext, self.key)
        dec = des_cipher.decrypt(enc['ciphertext_hex'], self.key)
        self.assertEqual(dec['plaintext'], plaintext)

    def test_roundtrip_long_text(self):
        """Any-length plaintext must roundtrip correctly (multi-block ECB mode)."""
        plaintext = "HELLO WORLD THIS IS A LONGER MESSAGE FOR DES"
        enc = des_cipher.encrypt(plaintext, self.key)
        dec = des_cipher.decrypt(enc['ciphertext_hex'], self.key)
        self.assertEqual(dec['plaintext'], plaintext)

    def test_roundtrip_short_text(self):
        """Short plaintext gets padded and must still recover correctly after decryption."""
        plaintext = "HI"
        enc = des_cipher.encrypt(plaintext, self.key)
        dec = des_cipher.decrypt(enc['ciphertext_hex'], self.key)
        self.assertEqual(dec['plaintext'], plaintext)

    def test_different_keys_give_different_ciphertexts(self):
        """The same plaintext encrypted with two different keys must produce different output."""
        plaintext = "HELLO"
        ct1 = des_cipher.encrypt(plaintext, bytes(range(8)))['ciphertext_hex']
        ct2 = des_cipher.encrypt(plaintext, bytes(range(8, 16)))['ciphertext_hex']
        self.assertNotEqual(ct1, ct2)

    def test_decrypt_invalid_hex_raises_error(self):
        """Passing a non-hex string to decrypt() must raise ValueError."""
        with self.assertRaises(ValueError):
            des_cipher.decrypt("NOTVALIDHEX!", self.key)

    def test_decrypt_wrong_length_raises_error(self):
        """A hex string whose byte length is not a multiple of 8 must raise ValueError."""
        with self.assertRaises(ValueError):
            des_cipher.decrypt("AABB", self.key)   # only 2 bytes

    def test_encrypt_wrong_key_length_raises_error(self):
        """Passing a key that is not 8 bytes must raise ValueError."""
        with self.assertRaises(ValueError):
            des_cipher.encrypt("HELLO", b'SHORT')

    def test_decrypt_wrong_key_length_raises_error(self):
        """Passing a key that is not 8 bytes to decrypt() must raise ValueError."""
        enc = des_cipher.encrypt("HELLO", self.key)
        with self.assertRaises(ValueError):
            des_cipher.decrypt(enc['ciphertext_hex'], b'SHORT')


class TestDESBlockInternals(unittest.TestCase):
    """Tests for the internal Feistel block functions."""

    def test_feistel_block_roundtrip(self):
        """Encrypt a 64-bit block then decrypt it — must recover the original bits exactly."""
        from ciphers.des.cipher import _feistel_encrypt_block, _feistel_decrypt_block
        key        = bytes(range(8))
        round_keys = des_cipher.generate_round_keys(key)
        original   = bytes_to_bits(b'ABCDEFGH')

        encrypted = _feistel_encrypt_block(original, round_keys)
        decrypted = _feistel_decrypt_block(encrypted, round_keys)

        self.assertEqual(decrypted, original)

    def test_encrypt_changes_the_bits(self):
        """Encrypted output must differ from the input (DES actually transforms data)."""
        from ciphers.des.cipher import _feistel_encrypt_block
        key        = bytes(range(8))
        round_keys = des_cipher.generate_round_keys(key)
        original   = bytes_to_bits(b'ABCDEFGH')
        encrypted  = _feistel_encrypt_block(original, round_keys)

        self.assertNotEqual(original, encrypted)

    def test_block_output_is_64_bits(self):
        """Encrypted block must always be exactly 64 bits."""
        from ciphers.des.cipher import _feistel_encrypt_block
        key        = bytes(range(8))
        round_keys = des_cipher.generate_round_keys(key)
        original   = bytes_to_bits(b'ABCDEFGH')
        encrypted  = _feistel_encrypt_block(original, round_keys)

        self.assertEqual(len(encrypted), 64)


class TestDESRoundtrip(unittest.TestCase):
    """
    Demonstrates the full DES flow in one place — useful as a learning reference.

    plaintext  →  encrypt()  →  ciphertext_hex
               →  decrypt()  →  original plaintext
    """

    def test_full_des_roundtrip_example(self):
        """Complete DES encrypt → decrypt roundtrip with a fixed key and message."""
        key       = bytes([0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1])
        plaintext = "Hello, DES!"

        encrypted = des_cipher.encrypt(plaintext, key)
        decrypted = des_cipher.decrypt(encrypted['ciphertext_hex'], key)

        # The decrypted text must exactly match the original
        self.assertEqual(decrypted['plaintext'], plaintext)
        # Ciphertext must not be the same as the plaintext hex
        self.assertNotEqual(encrypted['ciphertext_hex'],
                            plaintext.encode('latin-1').hex().upper())


if __name__ == '__main__':
    unittest.main(verbosity=2)
