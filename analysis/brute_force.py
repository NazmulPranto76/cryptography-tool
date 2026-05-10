# analysis/brute_force.py
# Tries to decrypt a ciphertext using all applicable techniques.
# Two limits apply simultaneously — the search stops when EITHER is hit:
#   timeout_seconds : wall-clock time limit
#   max_attempts    : maximum number of key combinations to try

import math
import time
import itertools

_now = time.perf_counter  

from ciphers.substitution.cipher import brute_force_attack as _sub_brute_force
from ciphers.double_transposition.cipher import decrypt as _dt_decrypt


# Common English word fragments that appear even when spaces are removed
_ENGLISH_MARKERS = [
    'THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL', 'CAN',
    'WAS', 'HAD', 'HIS', 'THAT', 'WITH', 'THIS', 'FROM', 'HAVE',
    'THEY', 'BEEN', 'WILL', 'WHEN', 'WHAT', 'WHICH', 'THEIR',
]

# How many key-pair combinations exist for each key length
# length k → k!×k! pairs (one k-element permutation for rows, one for columns)
_COMBINATIONS_PER_LENGTH = {k: math.factorial(k) ** 2 for k in range(2, 8)}


def _total_combinations_up_to(max_len):
    # Input:  5
    # Output: 4 + 36 + 576 + 14400 = 15016
    return sum(_COMBINATIONS_PER_LENGTH[k] for k in range(2, max_len + 1))


def _max_key_length_reachable(max_attempts):
    # Input:  616
    # Output: 4  (lengths 2+3+4 = 616 combinations, just fits within 616)
    cumulative = 0
    for k in range(2, 8):
        cumulative += _COMBINATIONS_PER_LENGTH[k]
        if cumulative >= max_attempts:
            return k
    return 7


def _looks_like_english(text):
    # Input:  "THEQUICKBROWNFOX"
    # Output: True if any common English fragment appears as a substring
    upper = text.upper()
    return any(marker in upper for marker in _ENGLISH_MARKERS)


def _try_substitution(ciphertext, deadline, max_attempts):
    # Input:  "ITSSG VGKSR", deadline, max_attempts (unused — always 1 attempt)
    # Output: result dict — frequency analysis makes one educated guess
    result = {
        'algorithm':       'Substitution',
        'attempted':       True,
        'elapsed_ms':      None,
        'found':           False,
        'guess':           None,
        'keys_tried':      1,
        'total_key_space': '26! ≈ 4×10²⁶',
        'note':            'Frequency analysis — maps most frequent cipher letters to most frequent English letters',
    }
    t0 = _now()
    attack = _sub_brute_force(ciphertext)
    result['elapsed_ms'] = (_now() - t0) * 1000
    result['guess'] = attack.get('guessed_plaintext', '')
    result['found'] = _looks_like_english(result['guess'])
    return result


def _try_double_transposition(ciphertext, deadline, max_attempts):
    # Input:  "XOHLEL", deadline timestamp, max_attempts (e.g. 616)
    # Output: result dict — tries key permutations, stopping at the first limit hit
    max_key_len = _max_key_length_reachable(max_attempts)
    total_space = _total_combinations_up_to(max_key_len)

    result = {
        'algorithm':       'Double Transposition',
        'attempted':       True,
        'elapsed_ms':      None,
        'found':           False,
        'guess':           None,
        'keys_tried':      0,
        'total_key_space': f'{total_space:,} combinations (key lengths 2–{max_key_len})',
        'note':            f'Trying all key permutations up to length {max_key_len}',
    }

    t0 = _now()
    ct_len = len(ciphertext)

    for key_len in range(2, max_key_len + 1):
        if _now() >= deadline or result['keys_tried'] >= max_attempts:
            result['note'] += ' — stopped early'
            break

        # Skip key lengths that don't divide evenly into the ciphertext length —
        if ct_len % key_len != 0:
            continue

        for k2 in itertools.permutations(range(1, key_len + 1)):
            if _now() >= deadline or result['keys_tried'] >= max_attempts:
                break
            for k1 in itertools.permutations(range(1, key_len + 1)):
                if _now() >= deadline or result['keys_tried'] >= max_attempts:
                    break
                result['keys_tried'] += 1
                try:
                    candidate = _dt_decrypt(ciphertext, list(k1), list(k2))
                    if _looks_like_english(candidate):
                        result['found'] = True
                        result['guess'] = candidate
                        result['note'] = f'Found — key1={list(k1)}, key2={list(k2)}'
                        break
                except Exception:
                    pass
            if result['found']:
                break
        if result['found']:
            break

    result['elapsed_ms'] = (_now() - t0) * 1000
    return result


def _skipped(algorithm, reason, key_space=''):
    # Input:  "AES-128", "reason", "2¹²⁸ keys"
    # Output: a result dict marked as not attempted
    return {
        'algorithm':       algorithm,
        'attempted':       False,
        'elapsed_ms':      None,
        'found':           False,
        'guess':           None,
        'keys_tried':      0,
        'total_key_space': key_space,
        'note':            reason,
    }


DEFAULT_TIMEOUT  = 60   # seconds
DEFAULT_ATTEMPTS = 616  # all permutations of key lengths 2, 3, and 4


def run_brute_force(ciphertext, timeout_seconds=DEFAULT_TIMEOUT, max_attempts=DEFAULT_ATTEMPTS):
    # Input:  "ITSSG VGKSR", 60, 616
    # Output: list of result dicts, one per algorithm
    # Both limits apply — the search stops when either is reached first.
    deadline = _now() + timeout_seconds
    results  = []

    if _now() < deadline:
        results.append(_try_substitution(ciphertext, deadline, max_attempts))

    if _now() < deadline:
        results.append(_try_double_transposition(ciphertext, deadline, max_attempts))

    results.append(_skipped(
        'DES (Simplified)',
        'Key space is 2⁶⁴ ≈ 1.8×10¹⁹ — not feasible to brute force',
        '2⁶⁴ ≈ 1.8×10¹⁹ keys',
    ))
    results.append(_skipped(
        'AES-128',
        'Key space is 2¹²⁸ — computationally infeasible even for supercomputers',
        '2¹²⁸ ≈ 3.4×10³⁸ keys',
    ))
    results.append(_skipped(
        'RSA-512',
        'Requires knowing the public modulus n — use the RSA menu factorization attack instead',
        'Depends on key size',
    ))
    results.append(_skipped(
        'ECC (ECDH)',
        'ECC here does key exchange only — no message ciphertext to brute force',
        'N/A',
    ))

    return results
