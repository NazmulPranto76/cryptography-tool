# analysis/capabilities.py

from ciphers.substitution.cipher import (
    generate_random_key as _sub_gen_key,
    encrypt as _sub_encrypt,
    decrypt as _sub_decrypt,
)
from ciphers.double_transposition.cipher import (
    encrypt as _dt_encrypt,
    decrypt as _dt_decrypt,
)
from ciphers.des.cipher import (
    generate_key as _des_gen_key,
    encrypt as _des_encrypt,
    decrypt as _des_decrypt,
)
from ciphers.aes.cipher import (
    generate_key as _aes_gen_key,
    encrypt as _aes_encrypt,
    decrypt as _aes_decrypt,
)
from ciphers.rsa.cipher import (
    generate_keys as _rsa_gen_keys,
    encrypt as _rsa_encrypt,
    decrypt as _rsa_decrypt,
)


# --- Substitution wrappers ---

def _setup_substitution():
    # Output: {'key': 'QWERTY...'} — a random 26-letter key
    return {'key': _sub_gen_key()}

def _enc_substitution(plaintext, ctx):
    # Input:  "HELLO", {'key': 'QWERTY...'}
    # Output: ("ITSSG", ctx)
    return _sub_encrypt(plaintext, ctx['key']), ctx

def _dec_substitution(ciphertext, ctx):
    # Input:  "ITSSG", {'key': 'QWERTY...'}
    # Output: "HELLO"
    return _sub_decrypt(ciphertext, ctx['key'])


# --- Double Transposition wrappers ---

def _setup_double_transposition():
    # Output: {'key1': [3,1,4,2], 'key2': [2,4,1,3]} — fixed demo keys
    return {'key1': [3, 1, 4, 2], 'key2': [2, 4, 1, 3]}

def _enc_double_transposition(plaintext, ctx):
    # Input:  "HELLO", {'key1': [...], 'key2': [...]}
    # Output: ("XOHLEL", ctx)
    _, ct = _dt_encrypt(plaintext, ctx['key1'], ctx['key2'])
    return ct, ctx

def _dec_double_transposition(ciphertext, ctx):
    # Input:  "XOHLEL", {'key1': [...], 'key2': [...]}
    # Output: "HELLOX"
    return _dt_decrypt(ciphertext, ctx['key1'], ctx['key2'])


# --- DES wrappers ---

def _setup_des():
    # Output: {'key_bytes': b'\xa3\xf7...'} — 8 random bytes
    return {'key_bytes': _des_gen_key()}

def _enc_des(plaintext, ctx):
    # Input:  "HI", {'key_bytes': b'...'}
    # Output: ("3A9CF1...", ctx)
    result = _des_encrypt(plaintext, ctx['key_bytes'])
    return result['ciphertext_hex'], ctx

def _dec_des(ciphertext_hex, ctx):
    # Input:  "3A9CF1...", {'key_bytes': b'...'}
    # Output: "HI"
    result = _des_decrypt(ciphertext_hex, ctx['key_bytes'])
    return result['plaintext']


# --- AES wrappers ---

def _setup_aes():
    # Output: {'key_bytes': b'\x2b\x7e...'} — 16 random bytes (AES-128)
    return {'key_bytes': _aes_gen_key(128)}

def _enc_aes(plaintext, ctx):
    # Input:  "HELLO", {'key_bytes': b'...'}
    # Output: ("8F3A...", ctx)
    result = _aes_encrypt(plaintext, ctx['key_bytes'])
    return result['ciphertext_hex'], ctx

def _dec_aes(ciphertext_hex, ctx):
    # Input:  "8F3A...", {'key_bytes': b'...'}
    # Output: "HELLO"
    result = _aes_decrypt(ciphertext_hex, ctx['key_bytes'])
    return result['plaintext']


# --- RSA wrappers ---

def _setup_rsa():
    # Output: {'e': 65537, 'd': ..., 'n': ..., ...} — full key pair (~512-bit modulus)
    return _rsa_gen_keys(bits=256)

def _enc_rsa(plaintext, ctx):
    # Input:  "HI", {'e': 65537, 'n': ...}
    # Output: ([1876543, ...], ctx)
    result = _rsa_encrypt(plaintext, ctx['e'], ctx['n'])
    return result['chunks'], ctx

def _dec_rsa(chunks, ctx):
    # Input:  [1876543, ...], {'d': ..., 'n': ...}
    # Output: "HI"
    return _rsa_decrypt(chunks, ctx['d'], ctx['n'])


# --- Algorithm registry ---
# Each entry describes one algorithm and provides normalized setup/encrypt/decrypt callables.
# 'can_encrypt' / 'can_decrypt' say whether the algorithm supports those operations.
# 'setup'   → returns a context dict (keys, params)
# 'encrypt' → (plaintext, ctx) → (ciphertext, ctx)
# 'decrypt' → (ciphertext, ctx) → plaintext_str

ALGORITHMS = [
    {
        'name':        'Substitution',
        'can_encrypt': True,
        'can_decrypt': True,
        'note':        'Random 26-letter key',
        'setup':       _setup_substitution,
        'encrypt':     _enc_substitution,
        'decrypt':     _dec_substitution,
    },
    {
        'name':        'Double Transposition',
        'can_encrypt': True,
        'can_decrypt': True,
        'note':        'Demo keys [3,1,4,2] / [2,4,1,3]',
        'setup':       _setup_double_transposition,
        'encrypt':     _enc_double_transposition,
        'decrypt':     _dec_double_transposition,
    },
    {
        'name':        'DES (Simplified)',
        'can_encrypt': True,
        'can_decrypt': True,
        'note':        'Random 8-byte key',
        'setup':       _setup_des,
        'encrypt':     _enc_des,
        'decrypt':     _dec_des,
    },
    {
        'name':        'AES-128',
        'can_encrypt': True,
        'can_decrypt': True,
        'note':        'Random 16-byte key',
        'setup':       _setup_aes,
        'encrypt':     _enc_aes,
        'decrypt':     _dec_aes,
    },
    {
        'name':        'RSA-512',
        'can_encrypt': True,
        'can_decrypt': True,
        'note':        'Key gen in setup (not timed)',
        'setup':       _setup_rsa,
        'encrypt':     _enc_rsa,
        'decrypt':     _dec_rsa,
    },
    {
        'name':        'ECC (ECDH)',
        'can_encrypt': False,
        'can_decrypt': False,
        'note':        'ECDH key exchange only — no message encryption',
        'setup':       None,
        'encrypt':     None,
        'decrypt':     None,
    },
]
