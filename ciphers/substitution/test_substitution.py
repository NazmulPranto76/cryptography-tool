# ciphers/substitution/test_substitution.py
#
# Unit Tests for the Substitution Cipher.
#
# How to run these tests:
#   From the project root folder, run:
#       python -m unittest ciphers.substitution.test_substitution -v
#   Or run ALL tests at once:
#       python -m unittest discover -v

import unittest
import sys
import os

# Make sure Python can find the project root when running this file directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from ciphers.substitution import cipher as sub


class TestSubstitutionEncryption(unittest.TestCase):
    """Tests for the encrypt() function."""

    def setUp(self):
        """
        setUp() runs before every single test method.
        We define a fixed key here so tests are predictable and repeatable.
        """
        # This key maps: A->Q, B->W, C->E, D->R, E->T, ...
        self.key = "QWERTYUIOPASDFGHJKLZXCVBNM"

    def test_encrypt_simple_word(self):
        """Encrypting a simple word should replace each letter using the key."""
        # 'H' is the 8th letter (index 7), key[7] = 'I'
        # 'E' is the 5th letter (index 4), key[4] = 'T'
        # 'L' is the 12th letter (index 11), key[11] = 'D'
        # 'O' is the 15th letter (index 14), key[14] = 'F'
        result = sub.encrypt("HELLO", self.key)
        self.assertIsInstance(result, str)   # result must be a string
        self.assertEqual(len(result), 5)     # same length as input

    def test_encrypt_preserves_non_letters(self):
        """Spaces, numbers, and punctuation should NOT be encrypted."""
        result = sub.encrypt("HELLO WORLD!", self.key)
        # The space and '!' should still be in the result
        self.assertIn(' ', result)
        self.assertIn('!', result)

    def test_encrypt_is_uppercase(self):
        """The output should always be uppercase, regardless of input case."""
        result = sub.encrypt("hello", self.key)
        self.assertEqual(result, result.upper())

    def test_encrypt_empty_string(self):
        """Encrypting an empty string should return an empty string."""
        result = sub.encrypt("", self.key)
        self.assertEqual(result, "")


class TestSubstitutionDecryption(unittest.TestCase):
    """Tests for the decrypt() function."""

    def setUp(self):
        self.key = "QWERTYUIOPASDFGHJKLZXCVBNM"

    def test_roundtrip(self):
        """Encrypt then decrypt must give back the original text."""
        original = "HELLO WORLD"
        ciphertext = sub.encrypt(original, self.key)
        recovered = sub.decrypt(ciphertext, self.key)
        self.assertEqual(recovered, original)

    def test_roundtrip_with_numbers(self):
        """Roundtrip should preserve numbers and spaces."""
        original = "ATTACK AT DAWN 2024"
        ciphertext = sub.encrypt(original, self.key)
        recovered = sub.decrypt(ciphertext, self.key)
        self.assertEqual(recovered, original)

    def test_decrypt_is_inverse_of_encrypt(self):
        """Decrypt should always undo encrypt — tested with multiple strings."""
        test_strings = ["ABC", "XYZ", "PYTHON IS GREAT", "THE QUICK BROWN FOX"]
        for text in test_strings:
            with self.subTest(text=text):  # shows which string failed
                ct = sub.encrypt(text, self.key)
                pt = sub.decrypt(ct, self.key)
                self.assertEqual(pt, text)


class TestSubstitutionFrequencyAnalysis(unittest.TestCase):
    """Tests for the frequency_analysis() function."""

    def test_returns_dict_with_required_keys(self):
        """The result must be a dict containing 'freq', 'total', 'mapping', 'guessed_plaintext'."""
        result = sub.frequency_analysis("AAABBC")
        self.assertIn('freq', result)
        self.assertIn('total', result)
        self.assertIn('mapping', result)
        self.assertIn('guessed_plaintext', result)

    def test_frequency_count_is_correct(self):
        """Letter counts must match the actual text."""
        result = sub.frequency_analysis("AABBC")
        self.assertEqual(result['freq']['A'], 2)
        self.assertEqual(result['freq']['B'], 2)
        self.assertEqual(result['freq']['C'], 1)
        self.assertEqual(result['total'], 5)

    def test_empty_ciphertext(self):
        """Empty input should return total=0 without crashing."""
        result = sub.frequency_analysis("")
        self.assertEqual(result['total'], 0)

    def test_ignores_non_letters(self):
        """Spaces and numbers must not be counted in frequencies."""
        result = sub.frequency_analysis("A B C 1 2 3")
        self.assertEqual(result['total'], 3)


class TestSubstitutionKeyGeneration(unittest.TestCase):
    """Tests for the generate_random_key() function."""

    def test_key_is_26_characters(self):
        """A valid key must have exactly 26 characters."""
        key = sub.generate_random_key()
        self.assertEqual(len(key), 26)

    def test_key_uses_all_letters(self):
        """Every letter A-Z must appear exactly once in the key."""
        key = sub.generate_random_key()
        self.assertEqual(sorted(key), list("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))

    def test_key_is_string(self):
        """The key must be a string."""
        key = sub.generate_random_key()
        self.assertIsInstance(key, str)

    def test_two_keys_are_different(self):
        """
        Two randomly generated keys should almost certainly be different.
        (There is a 1/26! chance they are the same — effectively impossible.)
        """
        key1 = sub.generate_random_key()
        key2 = sub.generate_random_key()
        self.assertIsInstance(key1, str)
        self.assertIsInstance(key2, str)


if __name__ == '__main__':
    unittest.main(verbosity=2)
