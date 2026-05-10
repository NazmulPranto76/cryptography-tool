# analysis/timing.py

import time
from .capabilities import ALGORITHMS

_RUNS = 5   # how many times each operation is repeated before averaging


def _roundtrip_ok(original, recovered):
    # Input:  "HELLO WORLD",  "HELLO WORLDXX"
    # Output: True if recovered starts with (or equals) original, ignoring case and spaces
    if recovered == original:
        return True
    orig = original.upper().replace(' ', '')
    rec  = recovered.upper().replace(' ', '')
    return rec.startswith(orig)


def run_timing_analysis(plaintext):
    # Input:  "HELLO WORLD"
    # Output: list of dicts, one per algorithm, each with:
    #           name, can_encrypt, can_decrypt, enc_ms, dec_ms, roundtrip_ok, note, error
    results = []

    for algo in ALGORITHMS:
        entry = {
            'name':         algo['name'],
            'can_encrypt':  algo['can_encrypt'],
            'can_decrypt':  algo['can_decrypt'],
            'note':         algo['note'],
            'enc_ms':       None,
            'dec_ms':       None,
            'roundtrip_ok': None,
            'error':        None,
        }

        if not algo['can_encrypt']:
            results.append(entry)
            continue

        try:
            # Setup generates keys — not included in enc_ms / dec_ms
            ctx = algo['setup']()

            ciphertext, ctx = algo['encrypt'](plaintext, ctx)

            t0 = time.perf_counter()
            for _ in range(_RUNS):
                ciphertext, ctx = algo['encrypt'](plaintext, ctx)
            entry['enc_ms'] = (time.perf_counter() - t0) / _RUNS * 1000

            # Time decryption and verify round-trip
            if algo['can_decrypt']:
                t0 = time.perf_counter()
                for _ in range(_RUNS):
                    recovered = algo['decrypt'](ciphertext, ctx)
                entry['dec_ms'] = (time.perf_counter() - t0) / _RUNS * 1000
                entry['roundtrip_ok'] = _roundtrip_ok(plaintext, recovered)

        except Exception as exc:
            entry['error'] = str(exc)

        results.append(entry)

    return results
