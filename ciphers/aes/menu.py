# ciphers/aes/menu.py
# CLI Menu for AES — supports AES-128, AES-192, and AES-256.

from utils.display_helpers import print_separator
from ciphers.aes.cipher import generate_key, key_expansion, encrypt, decrypt, _state_to_bytes


def run_menu():
    """Show the AES sub-menu and handle user choices."""
    print_separator("AES (From Scratch)")
    print("  Block: 128 bits (16 bytes) — fixed for all AES variants")
    print("  Supported key sizes: 128-bit (10 rounds), 192-bit (12 rounds), 256-bit (14 rounds)\n")

    print("  Select AES variant:")
    print("    1 = AES-128  (16-byte key, 10 rounds)")
    print("    2 = AES-192  (24-byte key, 12 rounds)")
    print("    3 = AES-256  (32-byte key, 14 rounds)")
    variant_choice = input("  Choice [1/2/3, default=1]: ").strip()
    key_size = {'2': 192, '3': 256}.get(variant_choice, 128)

    key_bytes = generate_key(key_size=key_size)
    round_keys = key_expansion(key_bytes)
    variant_label = f"AES-{key_size}"

    print(f"\n  Variant : {variant_label}")
    print(f"  Key (hex): {key_bytes.hex().upper()}")
    print(f"  Round keys generated: {len(round_keys)}\n")

    last_ct_hex = None

    while True:
        print(f"\n  --- {variant_label} Options ---")
        print("  1. Encrypt  (any length plaintext)")
        print("  2. Decrypt")
        print("  3. Show All Round Keys")
        print("  0. Back to main menu")
        choice = input("  Your choice: ").strip()

        if choice == '1':
            plaintext = input("  Enter plaintext (any length): ")
            result = encrypt(plaintext, key_bytes)
            print(f"\n  Variant      : {result['variant']}")
            print(f"  Plaintext    : {plaintext}")
            print(f"  Blocks used  : {result['num_blocks']}")
            print(f"  Ciphertext   : {result['ciphertext_hex']}")
            last_ct_hex = result['ciphertext_hex']
            verify = decrypt(result['ciphertext_hex'], key_bytes)
            print(f"  Roundtrip    : {verify['plaintext']}")

        elif choice == '2':
            default = f"(Enter for last: {last_ct_hex})" if last_ct_hex else ""
            ct_input = input(f"  Enter ciphertext hex {default}: ").strip()
            if not ct_input and last_ct_hex:
                ct_input = last_ct_hex
            try:
                result = decrypt(ct_input, key_bytes)
                print(f"\n  Decrypted: {result['plaintext']}")
            except ValueError as e:
                print(f"  Error: {e}")

        elif choice == '3':
            print(f"\n  All {len(round_keys)} Round Keys (hex):")
            for i, rk in enumerate(round_keys):
                print(f"    Round {i:2d}: {_state_to_bytes(rk).hex().upper()}")

        elif choice == '0':
            break
        else:
            print("  Invalid choice.")
