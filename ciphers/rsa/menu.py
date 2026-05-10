# ciphers/rsa/menu.py

from utils.display_helpers import print_separator
from ciphers.rsa import cipher as rsa_cipher


def run_menu():
    """Show the RSA sub-menu and handle user choices."""
    print_separator("RSA Public Key Cryptography")
    print("  Public key (e, n): encrypts.  Private key (d, n): decrypts.")
    print("  Any-length messages: split into chunks smaller than n, each encrypted separately.\n")

    rsa_keys = {}
    last_chunks = None

    while True:
        print("\n  --- RSA Options ---")
        print("  1. Generate Key Pair")
        print("  2. Encrypt  (any length message)")
        print("  3. Decrypt")
        print("  4. Factorization Attack Demo  (small key)")
        print("  0. Back to main menu")
        choice = input("  Your choice: ").strip()

        if choice == '1':
            print("\n  1 = 512-bit  (fast, educational)")
            print("  2 = 1024-bit (slower)")
            sc = input("  Key size [1/2, default=1]: ").strip()
            bits = 512 if sc == '2' else 256
            label = "1024-bit" if sc == '2' else "512-bit"
            print(f"\n  Generating {label} RSA key pair...")
            rsa_keys = rsa_cipher.generate_keys(bits=bits)
            print(f"  p   = {rsa_keys['p']}")
            print(f"  q   = {rsa_keys['q']}")
            print(f"  n   = {rsa_keys['n']}")
            print(f"\n  Public  key (e, n): e = {rsa_keys['e']}")
            print(f"  Private key (d, n): d = {rsa_keys['d']}")

        elif choice == '2':
            if not rsa_keys:
                print("  Please generate a key pair first (option 1).")
                continue
            message = input("  Enter message (any length): ")
            result = rsa_cipher.encrypt(message, rsa_keys['e'], rsa_keys['n'])
            print(f"\n  Plaintext     : {message}")
            print(f"  Chunk size    : {result['chunk_size_bytes']} bytes")
            print(f"  Total chunks  : {result['num_chunks']}")
            for i, chunk in enumerate(result['chunks']):
                print(f"  Chunk {i+1} (int): {chunk}")
            last_chunks = result['chunks']

        elif choice == '3':
            if not rsa_keys:
                print("  Please generate a key pair first (option 1).")
                continue
            if last_chunks is None:
                print("  No ciphertext to decrypt. Please encrypt something first.")
                continue
            try:
                plaintext = rsa_cipher.decrypt(last_chunks, rsa_keys['d'], rsa_keys['n'])
                print(f"\n  Decrypted: {plaintext}")
            except Exception as e:
                print(f"  Decryption failed: {e}")

        elif choice == '4':
            print("\n  Generating small demo RSA key (16-bit primes)...")
            demo = rsa_cipher.generate_keys(bits=16)
            print(f"  n (public) = {demo['n']},  e = {demo['e']}")
            print(f"  (Secret p = {demo['p']}, q = {demo['q']})")
            print("\n  Running Pollard's Rho factorization...")
            result = rsa_cipher.factorization_attack(demo['n'], demo['e'])
            print(f"\n  {result['note']}\n")
            if result['success']:
                print(f"  SUCCESS after {result['attempts']} attempt(s)!")
                print(f"  Found p = {result['p']},  q = {result['q']}")
                print(f"  Recovered d = {result['d_recovered']}")
                print(f"  Verified d == real d? {result['d_recovered'] == demo['d']}")
            else:
                print(f"  Attack failed after {result['attempts']} attempts. Try again.")

        elif choice == '0':
            break
        else:
            print("  Invalid choice.")
