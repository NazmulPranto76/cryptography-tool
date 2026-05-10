# ciphers/des/test_des.py
#
# Unit Tests for the Simplified DES Cipher.
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
    """Tests for generate_key() and generate_round_keys()."""

    def test_key_is_8_bytes(self):
        """Generated key must be exactly 8 bytes (64 bits)."""
        key = des_cipher.generate_key()
        self.assertEqual(len(key), 8)

    def test_key_is_bytes_type(self):
        """Key must be a bytes object, not a string or list."""
        key = des_cipher.generate_key()
        self.assertIsInstance(key, bytes)

    def test_round_keys_count(self):
        """generate_round_keys() must return exactly 8 round keys."""
        key = des_cipher.generate_key()
        round_keys = des_cipher.generate_round_keys(key, num_rounds=8)
        self.assertEqual(len(round_keys), 8)

    def test_each_round_key_is_32_bits(self):
        """Each round key must be a list of exactly 32 bits (0s and 1s)."""
        key = des_cipher.generate_key()
        round_keys = des_cipher.generate_round_keys(key)
        for i, rk in enumerate(round_keys):
            with self.subTest(round=i + 1):
                self.assertEqual(len(rk), 32)
                # All values must be 0 or 1
                self.assertTrue(all(b in (0, 1) for b in rk))

    def test_round_keys_are_different(self):
        """Different rounds should produce different round keys (rotation changes them)."""
        key = bytes([0b10101010] * 8)  # a fixed key for reproducibility
        round_keys = des_cipher.generate_round_keys(key)
        # Not all round keys should be identical (rotation should change them)
        unique_keys = [tuple(rk) for rk in round_keys]
        # At least some should differ (all being the same would be a bug)
        self.assertGreater(len(set(unique_keys)), 1)


class TestDESEncryptDecrypt(unittest.TestCase):
    """Tests for the main encrypt() and decrypt() functions."""

    def setUp(self):
        """Use a fixed key so tests are reproducible."""
        # A fixed 8-byte key: bytes 0x00 through 0x07
        self.key = bytes(range(8))

    def test_encrypt_returns_dict_with_required_keys(self):
        """encrypt() must return a dict with 'ciphertext_hex', 'round_keys', etc."""
        result = des_cipher.encrypt("HELLO", self.key)
        self.assertIn('ciphertext_hex', result)
        self.assertIn('round_keys', result)
        self.assertIn('num_blocks', result)

    def test_ciphertext_length_is_multiple_of_16_hex(self):
        """Ciphertext hex must be a multiple of 16 chars (8 bytes per block)."""
        result = des_cipher.encrypt("HELLO WORLD THIS IS A LONG MESSAGE", self.key)
        self.assertEqual(len(result['ciphertext_hex']) % 16, 0)

    def test_roundtrip_simple(self):
        """Encrypt then decrypt must recover the original plaintext."""
        plaintext = "ABCDEFGH"
        enc = des_cipher.encrypt(plaintext, self.key)
        dec = des_cipher.decrypt(enc['ciphertext_hex'], self.key)
        self.assertEqual(dec['plaintext'], plaintext)

    def test_roundtrip_long_text(self):
        """Any-length plaintext must roundtrip correctly (multi-block ECB)."""
        plaintext = "HELLO WORLD THIS IS A LONGER MESSAGE FOR DES"
        enc = des_cipher.encrypt(plaintext, self.key)
        dec = des_cipher.decrypt(enc['ciphertext_hex'], self.key)
        self.assertEqual(dec['plaintext'], plaintext)

    def test_roundtrip_with_short_text(self):
        """Short plaintext gets padded and must still recover correctly."""
        plaintext = "HI"
        enc = des_cipher.encrypt(plaintext, self.key)
        dec = des_cipher.decrypt(enc['ciphertext_hex'], self.key)
        self.assertEqual(dec['plaintext'], plaintext)

    def test_different_keys_give_different_ciphertexts(self):
        """The same plaintext with different keys must produce different ciphertexts."""
        plaintext = "HELLO"
        ct1 = des_cipher.encrypt(plaintext, bytes(range(8)))['ciphertext_hex']
        ct2 = des_cipher.encrypt(plaintext, bytes(range(8, 16)))['ciphertext_hex']
        self.assertNotEqual(ct1, ct2)

    def test_decrypt_invalid_hex_raises_error(self):
        """Passing a non-hex string to decrypt() must raise ValueError."""
        with self.assertRaises(ValueError):
            des_cipher.decrypt("NOTVALIDHEX!", self.key)

    def test_decrypt_wrong_length_raises_error(self):
        """A hex string not a multiple of 16 chars must raise ValueError."""
        with self.assertRaises(ValueError):
            des_cipher.decrypt("AABB", self.key)  # 2 bytes, not a multiple of 8


class TestFeistelInternals(unittest.TestCase):
    """Tests for the internal Feistel block functions."""

    def test_feistel_block_roundtrip(self):
        """Encrypt a bit block then decrypt — must return the original bits."""
        from ciphers.des.cipher import _feistel_encrypt_block, _feistel_decrypt_block
        key = bytes(range(8))
        round_keys = des_cipher.generate_round_keys(key)
        original_bits = bytes_to_bits(b'ABCDEFGH')

        encrypted = _feistel_encrypt_block(original_bits, round_keys)
        decrypted = _feistel_decrypt_block(encrypted, round_keys)

        self.assertEqual(decrypted, original_bits)

    def test_encrypt_changes_the_bits(self):
        """Encryption must change the bit pattern (not return the input unchanged)."""
        from ciphers.des.cipher import _feistel_encrypt_block
        key = bytes(range(8))
        round_keys = des_cipher.generate_round_keys(key)
        original_bits = bytes_to_bits(b'ABCDEFGH')
        encrypted = _feistel_encrypt_block(original_bits, round_keys)
        self.assertNotEqual(original_bits, encrypted)


if __name__ == '__main__':
    unittest.main(verbosity=2)
