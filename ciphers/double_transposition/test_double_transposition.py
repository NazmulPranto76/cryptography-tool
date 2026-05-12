import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from ciphers.double_transposition import cipher as dt


class TestParseKey(unittest.TestCase):

    def test_valid_key(self):
        self.assertEqual(dt.parse_key("3 1 4 2"), [3, 1, 4, 2])

    def test_invalid_key_with_letters(self):
        self.assertIsNone(dt.parse_key("a b c"))

    def test_single_element_key(self):
        self.assertEqual(dt.parse_key("1"), [1])


class TestTransposeFunctions(unittest.TestCase):

    def test_row_transpose_direct_order(self):
        # key [3,1,2] means: read row 3 first, then row 1, then row 2
        from ciphers.double_transposition.cipher import _row_transpose_encrypt
        key = [3, 1, 2]
        text = "ABCDEFGHI"  # exactly 3 rows of 3: ABC / DEF / GHI
        result = _row_transpose_encrypt(text, key)
        self.assertEqual(result, "GHIABCDEF")

    def test_col_transpose_direct_order(self):
        # key [3,1,2]: read all of col3 (CFI), then col1 (ADG), then col2 (BEH)
        from ciphers.double_transposition.cipher import _col_transpose_encrypt
        key = [3, 1, 2]
        text = "ABCDEFGHI"  # 3x3 grid: row1=ABC, row2=DEF, row3=GHI
        result = _col_transpose_encrypt(text, key)
        self.assertEqual(result, "CFIADGBEH")

    def test_row_transpose_roundtrip(self):
        from ciphers.double_transposition.cipher import _row_transpose_encrypt, _row_transpose_decrypt
        key = [3, 1, 4, 2]
        text = "HELLOWORLD"
        encrypted = _row_transpose_encrypt(text, key)
        decrypted = _row_transpose_decrypt(encrypted, key)
        self.assertTrue(decrypted.startswith(text))

    def test_col_transpose_roundtrip(self):
        from ciphers.double_transposition.cipher import _col_transpose_encrypt, _col_transpose_decrypt
        key = [3, 1, 4, 2]
        text = "HELLOWORLD"
        encrypted = _col_transpose_encrypt(text, key)
        decrypted = _col_transpose_decrypt(encrypted, key)
        self.assertTrue(decrypted.startswith(text))

    def test_col_output_length_is_padded_multiple(self):
        from ciphers.double_transposition.cipher import _col_transpose_encrypt
        key = [3, 1, 4, 2]
        text = "HELLO"
        result = _col_transpose_encrypt(text, key)
        self.assertEqual(len(result) % len(key), 0)

    def test_row_output_length_is_padded_multiple(self):
        from ciphers.double_transposition.cipher import _row_transpose_encrypt
        key = [3, 1, 4, 2]
        text = "HELLO"
        result = _row_transpose_encrypt(text, key)
        self.assertEqual(len(result) % len(key), 0)


class TestDoubleTranspositionEncrypt(unittest.TestCase):

    def setUp(self):
        self.key1 = [3, 1, 4, 2]
        self.key2 = [2, 4, 1, 3]

    def test_encrypt_returns_tuple(self):
        result = dt.encrypt("HELLO", self.key1, self.key2)
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 2)

    def test_encrypt_output_is_uppercase(self):
        _, ciphertext = dt.encrypt("hello world", self.key1, self.key2)
        self.assertEqual(ciphertext, ciphertext.upper())

    def test_encrypt_strips_spaces(self):
        _, ct1 = dt.encrypt("HELLO WORLD", self.key1, self.key2)
        _, ct2 = dt.encrypt("HELLOWORLD", self.key1, self.key2)
        self.assertEqual(ct1, ct2)

    def test_encrypt_changes_the_text(self):
        text = "HELLOWORLD"
        _, ciphertext = dt.encrypt(text, self.key1, self.key2)
        self.assertNotEqual(text, ciphertext.replace('X', ''))


class TestDoubleTranspositionDecrypt(unittest.TestCase):

    def setUp(self):
        self.key1 = [3, 1, 4, 2]
        self.key2 = [2, 4, 1, 3]

    def test_roundtrip(self):
        original = "HELLOWORLD"
        _, ciphertext = dt.encrypt(original, self.key1, self.key2)
        recovered = dt.decrypt(ciphertext, self.key1, self.key2)
        self.assertTrue(recovered.startswith(original))

    def test_roundtrip_multiple_inputs(self):
        test_cases = [
            "ATTACKATDAWN",
            "CRYPTOGRAPHY",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ]
        for text in test_cases:
            with self.subTest(text=text):
                _, ct = dt.encrypt(text, self.key1, self.key2)
                recovered = dt.decrypt(ct, self.key1, self.key2)
                self.assertTrue(recovered.startswith(text))

    def test_different_keys_give_different_results(self):
        text = "HELLOWORLD"
        _, ct1 = dt.encrypt(text, [3, 1, 4, 2], [2, 4, 1, 3])
        _, ct2 = dt.encrypt(text, [1, 2, 3, 4], [4, 3, 2, 1])
        self.assertNotEqual(ct1, ct2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
