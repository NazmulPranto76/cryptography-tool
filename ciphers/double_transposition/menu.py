# ciphers/double_transposition/menu.py
# CLI Menu for Double Transposition Cipher.

from utils.display_helpers import print_separator, print_freq_chart, get_letter_frequencies
from . import cipher as dt

def run_menu():
    print_separator("========== Double Transposition Cipher ==========")

    key1_str = input("  Enter Key 1 (e.g. '3 1 4 2'): ").strip()
    key2_str = input("  Enter Key 2 (e.g. '2 4 1 3'): ").strip()
    
    # converting to list
    key1 = dt.parse_key(key1_str)
    key2 = dt.parse_key(key2_str)

    if key1 is None or key2 is None:
        print("  ERROR: Keys must be space-separated integers. Example: '3 1 4 2'")
        return

    print(f"\n  Key 1: {key1}")
    print(f"  Key 2: {key2}")

    while True:
        print("\n  --- Double Transposition Options ---")
        print("  1. Encrypt")
        print("  2. Decrypt")
        print("  3. Frequency Analysis (shows letters are NOT changed)")
        print("  0. Back to main menu")
        choice = input("  Your choice: ").strip()

        if choice == '1':
            plaintext = input("  Enter plaintext to encrypt: ")
            after_first, ciphertext = dt.encrypt(plaintext, key1, key2)

            print(f"\n  Plaintext          : {plaintext.upper().replace(' ', '')}")
            print(f"  After 1st transpose: {after_first}")
            print(f"  Final ciphertext   : {ciphertext}")

            recovered = dt.decrypt(ciphertext, key1, key2)
            print(f"  Roundtrip check    : {recovered}")

        elif choice == '2':
            ciphertext = input("  Enter ciphertext to decrypt: ").strip().upper()
            plaintext = dt.decrypt(ciphertext, key1, key2)
            print(f"\n  Ciphertext : {ciphertext}")
            print(f"  Decrypted  : {plaintext}")

        elif choice == '3':
            text = input("  Enter text to analyze: ").strip().upper()
            freq, total = get_letter_frequencies(text)
            print_freq_chart(freq, total)

        elif choice == '0':
            break
        else:
            print("  Invalid choice.")