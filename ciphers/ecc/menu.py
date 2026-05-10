# ciphers/ecc/menu.py
# CLI Menu for ECC Diffie-Hellman Key Exchange.

from utils.display_helpers import print_separator
from . import cipher as ecc_cipher

# Default demo curve: y^2 = x^3 + 2x + 2 (mod 17)
# Generator point G = (5, 1), Order = 19
DEFAULT_CURVE = {'p': 17, 'a': 2, 'b': 2, 'G': (5, 1), 'n': 19}


def run_menu():
    print_separator("ECC — Elliptic Curve Diffie-Hellman")
    print("  Curve equation: y^2 ≡ x^3 + ax + b  (mod p)")
    print("  Default demo curve: y^2 = x^3 + 2x + 2 (mod 17)")
    print("  Generator G = (5, 1),  Order n = 19\n")

    use_custom = input("  Use custom curve parameters? (y/N): ").strip().lower()
    if use_custom == 'y':
        try:
            p = int(input("  Prime p: "))
            a = int(input("  Coefficient a: "))
            b = int(input("  Coefficient b: "))
            gx = int(input("  Generator Gx: "))
            gy = int(input("  Generator Gy: "))
            n = int(input("  Order of G (n): "))
            curve = {'p': p, 'a': a, 'b': b, 'G': (gx, gy), 'n': n}
        except ValueError:
            print("  Invalid input. Using default curve.")
            curve = DEFAULT_CURVE
    else:
        curve = DEFAULT_CURVE

    print(f"\n  Curve: y^2 = x^3 + {curve['a']}x + {curve['b']} (mod {curve['p']})")
    print(f"  Generator G = {curve['G']},  Order n = {curve['n']}")

    while True:
        print("\n  --- ECC Options ---")
        print("  1. Show All Points on the Curve")
        print("  2. ECDH Key Exchange")
        print("  0. Back to main menu")
        choice = input("  Your choice: ").strip()

        if choice == '1':
            print("\n  Computing all curve points (may take a moment for large p)...")
            points = ecc_cipher.get_all_curve_points(curve['a'], curve['b'], curve['p'])
            print(f"\n  Found {len(points)} affine points (+ 1 point at infinity):")
            # Print in rows of 4 for readability
            for i in range(0, len(points), 4):
                row_points = points[i : i + 4]
                print("   ", "   ".join(str(pt) for pt in row_points))
            print("  + Point at infinity (O) — the identity element")

        elif choice == '2':
            result = ecc_cipher.ecdh_key_exchange(
                curve['G'], curve['a'], curve['p'], curve['n']
            )
            print("\n  --- ECDH Key Exchange ---")
            print(f"\n  Alice's private key (a):   {result['alice_private']}")
            print(f"  Alice's public key  (A=aG): {result['alice_public']}")
            print(f"\n  Bob's   private key (b):   {result['bob_private']}")
            print(f"  Bob's   public key  (B=bG): {result['bob_public']}")
            print(f"\n  Alice computes: a * B = {result['alice_shared']}")
            print(f"  Bob   computes: b * A = {result['bob_shared']}")
            print(f"\n  Shared secrets match: {result['secrets_match']}")

            if result['secrets_match']:
                print(f"  Shared Secret: {result['alice_shared']}")
                print("\n  Both arrived at the same point!")
                print("  An eavesdropper only sees G, A, B — they cannot")
                print("  recover the private keys without solving the discrete log problem.")

        elif choice == '0':
            break
        else:
            print("  Invalid choice.")
