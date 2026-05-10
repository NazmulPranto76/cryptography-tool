# main.py — CLI entry point
# python main.py          → interactive menu
# python -m unittest discover -v  → all tests

import time

from utils.display_helpers import print_separator

from ciphers.substitution.menu          import run_menu as substitution_menu
from ciphers.double_transposition.menu  import run_menu as transposition_menu
from ciphers.des.menu                   import run_menu as des_menu
from ciphers.aes.menu                   import run_menu as aes_menu
from ciphers.rsa.menu                   import run_menu as rsa_menu
from ciphers.ecc.menu                   import run_menu as ecc_menu
from analysis.menu                      import run_menu as analysis_menu

from ciphers.substitution.cipher        import encrypt as sub_encrypt, generate_random_key
from ciphers.double_transposition.cipher import encrypt as trans_encrypt
from ciphers.des.cipher                 import generate_key as des_gen_key, encrypt as des_encrypt
from ciphers.aes.cipher                 import generate_key as aes_gen_key, encrypt as aes_encrypt
from ciphers.rsa.cipher                 import generate_keys as rsa_gen_keys, encrypt as rsa_encrypt
from ciphers.ecc.cipher                 import ecdh_key_exchange


# Standard academic security ratings — not subjective opinions.
SECURITY_NOTES = {
    "Substitution":         ("~26 bits (trivially broken by freq. analysis)", "Very Weak"),
    "Double Transposition": ("~26 bits (freq. analysis possible)",            "Weak"),
    "DES (Simplified)":     ("64-bit block / 64-bit key",                     "Educational only"),
    "AES-128":              ("128-bit key - unbroken, NIST standard",         "Strong"),
    "RSA-512":              ("512-bit modulus - factorable, avoid in prod.",   "Moderate (use 2048+)"),
    "ECC (p=17 demo)":      ("Tiny demo curve - real curves use 256+ bit p",  "Demo only"),
}


def _time_function(fn, *args, runs=5):
    """Average fn's runtime over `runs` iterations; returns milliseconds."""
    start = time.perf_counter()
    for _ in range(runs):
        fn(*args)
    end = time.perf_counter()
    return ((end - start) / runs) * 1000


def performance_analysis():
    """Benchmark all six algorithms and print a comparison table with security notes."""
    print_separator("Performance & Security Analysis")
    print("  Times are averaged over 5 runs to reduce noise.")
    print("  Press Enter to use the default test sentence.\n")

    user_input = input("  Enter your own plaintext (or press Enter for default): ").strip()
    DEFAULT = "HELLO WORLD THIS IS A CRYPTOGRAPHY PERFORMANCE TEST"
    TEST_TEXT = user_input if user_input else DEFAULT
    print(f"\n  Testing on: \"{TEST_TEXT}\"\n")
    results = []

    print("  [1/6] Substitution Cipher ...", end=" ", flush=True)
    sub_key = generate_random_key()
    ms = _time_function(sub_encrypt, TEST_TEXT, sub_key)
    results.append(("Substitution", f"{ms:.4f} ms", *SECURITY_NOTES["Substitution"]))
    print("done")

    print("  [2/6] Double Transposition  ...", end=" ", flush=True)
    key1 = [3, 1, 4, 2, 5]
    key2 = [2, 5, 1, 4, 3]
    ms = _time_function(trans_encrypt, TEST_TEXT, key1, key2)
    results.append(("Double Transposition", f"{ms:.4f} ms", *SECURITY_NOTES["Double Transposition"]))
    print("done")

    print("  [3/6] Simplified DES        ...", end=" ", flush=True)
    des_key = des_gen_key()
    ms = _time_function(des_encrypt, TEST_TEXT[:8], des_key)  # single block for timing
    results.append(("DES (Simplified)", f"{ms:.4f} ms", *SECURITY_NOTES["DES (Simplified)"]))
    print("done")

    print("  [4/6] AES-128               ...", end=" ", flush=True)
    aes_key = aes_gen_key()
    ms = _time_function(aes_encrypt, TEST_TEXT, aes_key)
    results.append(("AES-128", f"{ms:.4f} ms", *SECURITY_NOTES["AES-128"]))
    print("done")

    print("  [5/6] RSA-512 (key gen + encrypt) ...", end=" ", flush=True)
    # Key generation dominates RSA timing, so we include it deliberately
    def rsa_keygen_and_encrypt():
        keys = rsa_gen_keys(bits=256)  # 512-bit modulus
        rsa_encrypt("Hi", keys['e'], keys['n'])
    ms = _time_function(rsa_keygen_and_encrypt, runs=3)  # fewer runs — it's slow
    results.append(("RSA-512", f"{ms:.1f} ms", *SECURITY_NOTES["RSA-512"]))
    print("done")

    print("  [6/6] ECC ECDH              ...", end=" ", flush=True)
    G = (5, 1)
    ms = _time_function(ecdh_key_exchange, G, 2, 17, 19)
    results.append(("ECC (p=17 demo)", f"{ms:.4f} ms", *SECURITY_NOTES["ECC (p=17 demo)"]))
    print("done")

    print_separator("Results")
    col1 = 22
    col2 = 14
    col3 = 42
    col4 = 22

    header = (f"  {'Algorithm':<{col1}} {'Avg Time':<{col2}} "
              f"{'Key / Security Info':<{col3}} {'Rating':<{col4}}")
    divider = "  " + "-" * (col1 + col2 + col3 + col4 + 3)

    print(header)
    print(divider)
    for algo, timing, key_info, rating in results:
        print(f"  {algo:<{col1}} {timing:<{col2}} {key_info:<{col3}} {rating:<{col4}}")

    print_separator("Security Summary")
    print("  Classical ciphers (Substitution, Double Transposition):")
    print("    Vulnerable to frequency analysis. Key space too small.")
    print("    Use for educational purposes only.")
    print()
    print("  Simplified DES:")
    print("    Educational implementation. Real DES (56-bit effective key) is")
    print("    considered broken. Replaced by AES in 2001.")
    print()
    print("  AES-128:")
    print("    Current gold standard for symmetric encryption.")
    print("    No practical attack known. Used in TLS, disk encryption, etc.")
    print()
    print("  RSA:")
    print("    Security depends on key size. 512-bit is breakable.")
    print("    Real applications use 2048-bit or 4096-bit keys.")
    print()
    print("  ECC:")
    print("    The demo curve (p=17) has only 18 points - trivially broken.")
    print("    Real ECC (e.g. P-256) offers 128-bit security with much")
    print("    smaller keys than RSA (256-bit ECC ~= 3072-bit RSA in strength).")
    print()
    print("  Performance observation:")
    print("    Classical ciphers are fastest (simple letter shuffling).")
    print("    AES is fast even for large data (hardware-optimized in real CPUs).")
    print("    RSA key generation is the slowest due to prime number search.")
    input("\n  Press Enter to return to the main menu...")


def main():
    """Main menu loop — dispatch to each cipher's menu or the performance analysis."""
    while True:
        print_separator()
        print("    === Cryptography Tool ===")
        print_separator()
        print("  Classical Ciphers:")
        print("    1. Substitution Cipher        (encrypt, decrypt, freq analysis, brute force)")
        print("    2. Double Transposition       (encrypt, decrypt, freq analysis)")
        print()
        print("  Symmetric (Secret Key) Ciphers:")
        print("    3. DES  — Simplified 8-Round Feistel  (encrypt, decrypt, round keys)")
        print("    4. AES  — AES-128 from scratch        (encrypt, decrypt, round keys)")
        print()
        print("  Public Key (Asymmetric) Ciphers:")
        print("    5. RSA  — Key gen, encrypt, decrypt, factorization attack")
        print("    6. ECC  — Domain params, all points, ECDH key exchange")
        print()
        print("  Analysis:")
        print("    7. Performance & Security Comparison (all algorithms)")
        print("    8. Analysis Suite  (timing analysis + brute force attempt)")
        print()
        print("    0. Exit")
        print_separator()

        choice = input("  Select [0-8]: ").strip()

        if   choice == '1':  substitution_menu()
        elif choice == '2':  transposition_menu()
        elif choice == '3':  des_menu()
        elif choice == '4':  aes_menu()
        elif choice == '5':  rsa_menu()
        elif choice == '6':  ecc_menu()
        elif choice == '7':  performance_analysis()
        elif choice == '8':  analysis_menu()
        elif choice == '0':
            print("\n  Goodbye!\n")
            break
        else:
            print("  Invalid choice. Please enter a number from 0 to 8.")


if __name__ == "__main__":
    main()
