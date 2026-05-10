# analysis/menu.py
# CLI menu for the Analysis Suite (timing + brute force).
# Called from main.py as option 8.

from utils.display_helpers import print_separator
from . import timing, brute_force, report


def run_menu():
    # Input:  user input via terminal
    # Output: none — interactive menu loop
    while True:
        print_separator("Analysis Suite")
        print("  1. Timing Analysis")
        print("     Encrypt and decrypt your text with every algorithm.")
        print("     Measures time for each step and checks round-trip correctness.")
        print()
        print("  2. Brute Force Analysis")
        print("     Attempt to decrypt a ciphertext using all applicable methods.")
        print("     Works on classical ciphers; modern ciphers are skipped with explanation.")
        print()
        print("  0. Back to main menu")
        print_separator()

        choice = input("  Select [0-2]: ").strip()

        if choice == '1':
            _run_timing()
        elif choice == '2':
            _run_brute_force()
        elif choice == '0':
            break
        else:
            print("  Invalid choice. Please enter 0, 1, or 2.")


def _run_timing():
    # Input:  user-supplied plaintext
    # Output: prints timing table via report.print_timing_report()
    print_separator("Timing Analysis")
    plaintext = input("  Enter plaintext: ").strip()
    if not plaintext:
        print("  No input. Returning.")
        return

    print("\n  Running all algorithms...")
    print("  (RSA key generation may take a few seconds — this is normal)\n")

    results = timing.run_timing_analysis(plaintext)
    report.print_timing_report(results)

    input("  Press Enter to continue...")


def _ask_int(prompt, default, min_val, max_val):
    # Input:  prompt string, default value, min, max
    # Output: validated integer from user (or default if user just pressed Enter)
    while True:
        raw = input(prompt).strip()
        if not raw:
            return default
        try:
            val = int(raw)
            if min_val <= val <= max_val:
                return val
            print(f"  Please enter a number between {min_val} and {max_val}.")
        except ValueError:
            print("  Please enter a whole number.")


def _run_brute_force():
    # Input:  user-supplied ciphertext, time limit, attempt count
    # Output: prints brute force report via report.print_brute_force_report()
    print_separator("Brute Force Analysis")
    print("  Both a time limit AND an attempt limit apply.")
    print("  The search stops as soon as either one is reached.\n")

    ciphertext = input("  Enter ciphertext: ").strip()
    if not ciphertext:
        print("  No input. Returning.")
        return

    print()
    print("  Key attempt guide for Double Transposition:")
    print(f"    {brute_force._total_combinations_up_to(4):>8,} attempts  →  key lengths 2-4  (default)")
    print(f"    {brute_force._total_combinations_up_to(5):>8,} attempts  →  key lengths 2-5")
    print(f"    {brute_force._total_combinations_up_to(6):>8,} attempts  →  key lengths 2-6  (slower)")
    print()

    timeout = _ask_int(
        f"  Time limit in seconds [default {brute_force.DEFAULT_TIMEOUT}, max 300]: ",
        default=brute_force.DEFAULT_TIMEOUT,
        min_val=1,
        max_val=300,
    )
    max_attempts = _ask_int(
        f"  Max key attempts [default {brute_force.DEFAULT_ATTEMPTS:,}]: ",
        default=brute_force.DEFAULT_ATTEMPTS,
        min_val=1,
        max_val=1_000_000,
    )

    print(f"\n  Starting... (limit: {timeout}s or {max_attempts:,} attempts, whichever comes first)\n")

    results = brute_force.run_brute_force(
        ciphertext,
        timeout_seconds=timeout,
        max_attempts=max_attempts,
    )
    report.print_brute_force_report(results, timeout_seconds=timeout)

    input("  Press Enter to continue...")
