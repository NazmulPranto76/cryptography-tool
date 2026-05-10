# ciphers/substitution/menu.py
#
# CLI Menu for the Substitution Cipher.

from utils.display_helpers import print_separator, print_freq_chart
from . import cipher as sub


def run_menu():
    print_separator("========== Substitution Cipher ==========")

    key_input = input("  Enter a 26-letter key (or press Enter for a random one): ").strip().upper()

    if not key_input:
        key_input = sub.generate_random_key()
        print(f"  Random key generated: {key_input}")
    elif len(key_input) != 26 or len(set(key_input)) != 26 or not key_input.isalpha():
        print("  ERROR: Key must be exactly 26 unique letters. Please try again.")
        return

    print(f"\n  Using key: {key_input}")

    while True:
        print("\n  --- Substitution Cipher Options ---")
        print("  1. Encrypt")
        print("  2. Decrypt")
        print("  3. Frequency Analysis (on ciphertext)")
        print("  4. Brute Force Attack Demo")
        print("  0. Back to main menu")
        choice = input("  Your choice: ").strip()

        if choice == '1':
            plaintext = input("  Enter plaintext to encrypt: ")
            ciphertext = sub.encrypt(plaintext, key_input)
            print(f"\n  Plaintext  : {plaintext.upper()}")
            print(f"  Key        : {key_input}")
            print(f"  Ciphertext : {ciphertext}")
            verified = sub.decrypt(ciphertext, key_input)
            print(f"  Roundtrip check (decrypt): {verified}")

        elif choice == '2':
            ciphertext = input("  Enter ciphertext to decrypt: ").strip()
            plaintext = sub.decrypt(ciphertext, key_input)
            print(f"\n  Ciphertext : {ciphertext.upper()}")
            print(f"  Decrypted  : {plaintext}")

        elif choice == '3':
            ciphertext = input("  Enter ciphertext to analyze: ").strip()
            result = sub.frequency_analysis(ciphertext)

            if result['total'] == 0:
                print("  No letters found. Please enter a ciphertext with letters.")
                continue

            print_freq_chart(result['freq'], result['total'])
            print("\n  Guessed mapping (Cipher Letter -> Likely Plaintext Letter):")
            for k, v in sorted(result['mapping'].items()):
                print(f"    {k} -> {v}", end="   ")
            print(f"\n\n  Guessed Plaintext: {result['guessed_plaintext']}")

        elif choice == '4':
            ciphertext = input("  Enter ciphertext to attack: ").strip()
            result = sub.brute_force_attack(ciphertext)

            if result['total'] == 0:
                print("  No letters found.")
                continue

            print(f"\n  {result['attack_note']}\n")
            print_freq_chart(result['freq'], result['total'])
            print(f"\n  Best guess plaintext: {result['guessed_plaintext']}")

        elif choice == '0':
            break
        else:
            print("  Invalid choice. Please enter 0, 1, 2, 3, or 4.")
