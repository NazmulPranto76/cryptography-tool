# ciphers/aes/test_aes.py
#
# Unit Tests for AES-128.
#
# Run from project root:
#   python -m unittest ciphers.aes.test_aes -v

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from ciphers.aes import cipher as aes_cipher


# A fixed 16-byte key used in tests (never use a fixed key in real applications!)
FIXED_KEY = bytes([
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c,
])


class TestGFMultiply(unittest.TestCase):
    """Tests for the GF(2^8) multiplication function used by MixColumns."""

    def test_multiply_by_one_is_identity(self):
        """Multiplying any value by 1 in GF(2^8) should return the same value."""
        from ciphers.aes.cipher import _gf_multiply
        for val in [0x00, 0x01, 0x57, 0xAB, 0xFF]:
            with self.subTest(val=val):
                self.assertEqual(_gf_multiply(val, 1), val)

    def test_multiply_by_zero_is_zero(self):
        """Multiplying any value by 0 in GF(2^8) should give 0."""
        from ciphers.aes.cipher import _gf_multiply
        for val in [0x01, 0x57, 0xFF]:
            with self.subTest(val=val):
                self.assertEqual(_gf_multiply(val, 0), 0)

    def test_known_gf_product(self):
        """
        Test a known GF(2^8) multiplication: 0x57 * 0x13 = 0xFE
        (from the AES specification examples).
        """
        from ciphers.aes.cipher import _gf_multiply
        self.assertEqual(_gf_multiply(0x57, 0x13), 0xFE)

    def test_result_fits_in_one_byte(self):
        """GF(2^8) multiplication must never exceed 255."""
        from ciphers.aes.cipher import _gf_multiply
        for a in [0xFF, 0x80, 0x01]:
            for b in [0xFF, 0x80, 0x02]:
                result = _gf_multiply(a, b)
                self.assertLessEqual(result, 255)
                self.assertGreaterEqual(result, 0)


class TestSBoxOperations(unittest.TestCase):
    """Tests for SubBytes and InvSubBytes."""

    def test_sub_bytes_changes_state(self):
        """SubBytes should change at least some values (0x00 maps to 0x63)."""
        from ciphers.aes.cipher import _sub_bytes
        state = [[0] * 4 for _ in range(4)]  # all zeros
        result = _sub_bytes(state)
        # 0x00 in S-Box maps to 0x63, so all cells should now be 0x63
        self.assertEqual(result[0][0], 0x63)

    def test_inv_sub_bytes_reverses_sub_bytes(self):
        """InvSubBytes must perfectly reverse SubBytes."""
        from ciphers.aes.cipher import _sub_bytes, _inv_sub_bytes, _bytes_to_state
        original_state = _bytes_to_state(bytes(range(16)))
        after_sub = _sub_bytes(original_state)
        recovered = _inv_sub_bytes(after_sub)
        self.assertEqual(recovered, original_state)


class TestShiftRows(unittest.TestCase):
    """Tests for ShiftRows and InvShiftRows."""

    def test_inv_shift_rows_reverses_shift_rows(self):
        """InvShiftRows must perfectly reverse ShiftRows."""
        from ciphers.aes.cipher import _shift_rows, _inv_shift_rows, _bytes_to_state
        state = _bytes_to_state(bytes(range(16)))
        shifted = _shift_rows(state)
        recovered = _inv_shift_rows(shifted)
        self.assertEqual(recovered, state)


class TestKeyExpansion(unittest.TestCase):
    """Tests for the key_expansion() function."""

    def test_returns_11_round_keys(self):
        """AES-128 needs exactly 11 round keys (round 0 through round 10)."""
        round_keys = aes_cipher.key_expansion(FIXED_KEY)
        self.assertEqual(len(round_keys), 11)

    def test_each_round_key_is_4x4(self):
        """Every round key must be a 4x4 matrix."""
        round_keys = aes_cipher.key_expansion(FIXED_KEY)
        for i, rk in enumerate(round_keys):
            with self.subTest(round=i):
                self.assertEqual(len(rk), 4)           # 4 rows
                self.assertEqual(len(rk[0]), 4)        # 4 columns

    def test_first_round_key_equals_original_key(self):
        """
        Round key 0 should equal the original key (written column by column).
        This is a known property of AES key expansion.
        """
        from ciphers.aes.cipher import _state_to_bytes
        round_keys = aes_cipher.key_expansion(FIXED_KEY)
        rk0_bytes = _state_to_bytes(round_keys[0])
        self.assertEqual(rk0_bytes, FIXED_KEY)


class TestAESEncryptDecrypt(unittest.TestCase):
    """Tests for the public encrypt() and decrypt() functions."""

    def test_encrypt_returns_dict_with_required_keys(self):
        """encrypt() must return a dict with the expected fields."""
        result = aes_cipher.encrypt("Hello AES", FIXED_KEY)
        self.assertIn('ciphertext_hex', result)
        self.assertIn('ciphertext_bytes', result)
        self.assertIn('round_keys', result)
        self.assertIn('num_blocks', result)

    def test_ciphertext_length_is_multiple_of_32_hex(self):
        """Ciphertext hex must be a multiple of 32 chars (16 bytes = 32 hex digits per block)."""
        result = aes_cipher.encrypt("Hello", FIXED_KEY)
        self.assertEqual(len(result['ciphertext_hex']) % 32, 0)

    def test_roundtrip_short_text(self):
        """Encrypt then decrypt a short string."""
        plaintext = "Hello AES!"
        enc = aes_cipher.encrypt(plaintext, FIXED_KEY)
        dec = aes_cipher.decrypt(enc['ciphertext_hex'], FIXED_KEY)
        self.assertEqual(dec['plaintext'], plaintext)

    def test_roundtrip_exact_block_size(self):
        """A plaintext that is exactly 16 bytes gets an extra padding block."""
        plaintext = "A" * 16  # exactly one block
        enc = aes_cipher.encrypt(plaintext, FIXED_KEY)
        dec = aes_cipher.decrypt(enc['ciphertext_hex'], FIXED_KEY)
        self.assertEqual(dec['plaintext'], plaintext)

    def test_roundtrip_multi_block(self):
        """A long plaintext spanning multiple blocks must roundtrip correctly."""
        plaintext = "The quick brown fox jumps over the lazy dog."
        enc = aes_cipher.encrypt(plaintext, FIXED_KEY)
        dec = aes_cipher.decrypt(enc['ciphertext_hex'], FIXED_KEY)
        self.assertEqual(dec['plaintext'], plaintext)

    def test_different_keys_produce_different_ciphertexts(self):
        """The same plaintext encrypted with two different keys must differ."""
        plaintext = "SAME TEXT"
        key2 = bytes([0x00] * 16)  # all zeros key
        ct1 = aes_cipher.encrypt(plaintext, FIXED_KEY)['ciphertext_hex']
        ct2 = aes_cipher.encrypt(plaintext, key2)['ciphertext_hex']
        self.assertNotEqual(ct1, ct2)

    def test_decrypt_invalid_hex_raises_error(self):
        """Passing garbage to decrypt() must raise ValueError."""
        with self.assertRaises(ValueError):
            aes_cipher.decrypt("NOT_VALID_HEX!!!", FIXED_KEY)

    def test_decrypt_wrong_block_length_raises_error(self):
        """A ciphertext that is not a multiple of 16 bytes must raise ValueError."""
        with self.assertRaises(ValueError):
            aes_cipher.decrypt("AABB", FIXED_KEY)  # 2 bytes, not 16


class TestAESMultiKeySize(unittest.TestCase):
    """Tests confirming AES-192 and AES-256 roundtrip correctly."""

    def test_aes192_roundtrip(self):
        """AES-192 (24-byte key) must encrypt and decrypt correctly."""
        key = aes_cipher.generate_key(key_size=192)
        self.assertEqual(len(key), 24)
        plaintext = "Testing AES-192 key size!"
        enc = aes_cipher.encrypt(plaintext, key)
        self.assertEqual(enc['variant'], 'AES-192')
        dec = aes_cipher.decrypt(enc['ciphertext_hex'], key)
        self.assertEqual(dec['plaintext'], plaintext)

    def test_aes256_roundtrip(self):
        """AES-256 (32-byte key) must encrypt and decrypt correctly."""
        key = aes_cipher.generate_key(key_size=256)
        self.assertEqual(len(key), 32)
        plaintext = "Testing AES-256 key size, the strongest variant!"
        enc = aes_cipher.encrypt(plaintext, key)
        self.assertEqual(enc['variant'], 'AES-256')
        dec = aes_cipher.decrypt(enc['ciphertext_hex'], key)
        self.assertEqual(dec['plaintext'], plaintext)

    def test_generate_key_invalid_size_raises(self):
        """generate_key() with an unsupported size must raise ValueError."""
        with self.assertRaises(ValueError):
            aes_cipher.generate_key(key_size=64)

    def test_all_three_variants_produce_different_ciphertexts(self):
        """AES-128, AES-192, AES-256 must produce different outputs for the same plaintext."""
        plaintext = "Same text, different keys"
        ct128 = aes_cipher.encrypt(plaintext, aes_cipher.generate_key(128))['ciphertext_hex']
        ct192 = aes_cipher.encrypt(plaintext, aes_cipher.generate_key(192))['ciphertext_hex']
        ct256 = aes_cipher.encrypt(plaintext, aes_cipher.generate_key(256))['ciphertext_hex']
        self.assertNotEqual(ct128, ct192)
        self.assertNotEqual(ct192, ct256)


class TestAESKnownVector(unittest.TestCase):
    """
    Test against a known AES-128 test vector from the NIST standard.
    This confirms our implementation matches the real AES standard.
    """

    def test_nist_encrypt_vector(self):
        """
        NIST FIPS 197 Appendix B test vector:
          Key:        2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
          Plaintext:  32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
          Ciphertext: 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32
        """
        from ciphers.aes.cipher import _encrypt_block, key_expansion
        key = bytes([
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ])
        plaintext = bytes([
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        ])
        expected_ciphertext = bytes([
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
        ])

        round_keys = key_expansion(key)
        result = _encrypt_block(plaintext, round_keys, nr=10)  # AES-128 = 10 rounds
        self.assertEqual(result, expected_ciphertext)


if __name__ == '__main__':
    unittest.main(verbosity=2)
