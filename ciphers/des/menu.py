# ciphers/des/menu.py
# CLI Menu for Real DES — 16-round Feistel cipher with standard tables.

from utils.display_helpers import print_separator
from utils.bit_helpers import bits_to_bytes
from ciphers.des import cipher as des_cipher


def run_menu():
    print_separator("DES (Data Encryption Standard — Educational)")
    print("  NOTE: Real DES structure — IP, 16 Feistel rounds, S-boxes, FP.")
    print("  DES is NOT secure for real use (56-bit key is too short).")
    print("  Block: 64 bits (8 bytes) | Key: 64 bits (56 effective) | Rounds: 16\n")

    key_bytes  = des_cipher.generate_key()
    round_keys = des_cipher.generate_round_keys(key_bytes)
    print(f"  Auto-generated key (hex): {key_bytes.hex().upper()}")
    print(f"  {len(round_keys)} round keys generated (48 bits each).\n")

    last_ct_hex = None

    while True:
        print("\n  --- DES Options ---")
        print("  1. Encrypt  (any length plaintext)")
        print("  2. Decrypt")
        print("  3. Show All Round Keys")
        print("  0. Back to main menu")
        choice = input("  Your choice: ").strip()

        if choice == '1':
            plaintext = input("  Enter plaintext (any length): ")
            result = des_cipher.encrypt(plaintext, key_bytes)
            print(f"\n  Plaintext   : {plaintext}")
            print(f"  Blocks used : {result['num_blocks']}")
            print(f"  Ciphertext  : {result['ciphertext_hex']}")
            last_ct_hex = result['ciphertext_hex']
            verify = des_cipher.decrypt(result['ciphertext_hex'], key_bytes)
            print(f"  Roundtrip   : {verify['plaintext']}")

        elif choice == '2':
            default = f"(Enter for last: {last_ct_hex})" if last_ct_hex else ""
            ct_input = input(f"  Enter ciphertext hex {default}: ").strip()
            if not ct_input and last_ct_hex:
                ct_input = last_ct_hex
            try:
                result = des_cipher.decrypt(ct_input, key_bytes)
                print(f"\n  Decrypted: {result['plaintext']}")
            except ValueError as e:
                print(f"  Error: {e}")

        elif choice == '3':
            print(f"\n  All {len(round_keys)} Round Keys (48 bits = 6 bytes each, shown as hex):")
            for i, rk in enumerate(round_keys):
                print(f"    Round {i + 1:2d}: {bits_to_bytes(rk).hex().upper()}")

        elif choice == '0':
            break
        else:
            print("  Invalid choice.")
