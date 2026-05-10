# ciphers/substitution/__init__.py
# Exposes the public API for the Substitution Cipher.
# Only pure logic is exported — no menu/display code.

from .cipher import encrypt, decrypt, frequency_analysis, brute_force_attack, generate_random_key
