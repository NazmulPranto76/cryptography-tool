# analysis/report.py
# Formats timing and brute-force results for display in the terminal.

from utils.display_helpers import print_separator


def print_timing_report(results):
    # Input:  list of result dicts from timing.run_timing_analysis()
    # Output: prints a formatted table to the terminal
    print_separator("Timing Analysis Results")

    col_name  = 22
    col_enc   = 13
    col_dec   = 13
    col_trip  = 10

    header = (
        f"  {'Algorithm':<{col_name}} "
        f"{'Encrypt':<{col_enc}} "
        f"{'Decrypt':<{col_dec}} "
        f"{'Roundtrip':<{col_trip}} "
        f"Notes"
    )
    divider = "  " + "-" * 80
    print(header)
    print(divider)

    for r in results:
        enc_str  = f"{r['enc_ms']:.3f} ms"  if r['enc_ms']  is not None else "N/A"
        dec_str  = f"{r['dec_ms']:.3f} ms"  if r['dec_ms']  is not None else "N/A"

        if r['roundtrip_ok'] is True:
            trip_str = "Yes"
        elif r['roundtrip_ok'] is False:
            trip_str = "FAIL"
        else:
            trip_str = "N/A"

        if r['error']:
            note = f"ERROR: {r['error'][:35]}"
        elif not r['can_encrypt']:
            note = r['note']
        else:
            note = r['note']

        print(
            f"  {r['name']:<{col_name}} "
            f"{enc_str:<{col_enc}} "
            f"{dec_str:<{col_dec}} "
            f"{trip_str:<{col_trip}} "
            f"{note}"
        )

    print()
    print("  Notes:")
    print("  - Times are single-run measurements (not averaged)")
    print("  - Key generation is done before timing starts (not included in Encrypt time)")
    print("  - Double Transposition may append 'X' padding — roundtrip checks for prefix match")
    print()


def print_brute_force_report(results, timeout_seconds):
    # Input:  list of result dicts from brute_force.run_brute_force(), and the timeout used
    # Output: prints a formatted report block per algorithm to the terminal
    print_separator(f"Brute Force Report  (timeout: {timeout_seconds}s)")

    for r in results:
        status = "Attempted" if r['attempted'] else "Skipped"
        found  = "YES — possible plaintext found" if r['found'] else ("No match" if r['attempted'] else "—")

        print(f"\n  Algorithm   : {r['algorithm']}")
        print(f"  Status      : {status}")
        if r['elapsed_ms'] is not None:
            print(f"  Time        : {r['elapsed_ms']:.1f} ms")
        tried = r.get('keys_tried', 0)
        space = r.get('total_key_space', '')
        print(f"  Keys tried  : {tried}  (total key space: {space})")
        print(f"  Result      : {found}")
        print(f"  Note        : {r['note']}")
        if r['guess']:
            truncated = r['guess'][:80] + ("..." if len(r['guess']) > 80 else "")
            print(f"  Best guess  : {truncated}")
        print("  " + "-" * 52)

    print()
    print("  Disclaimer: this brute force is an educational demo.")
    print("  Frequency analysis works on substitution ciphers; all")
    print("  others (DES, AES, RSA, ECC) are not attackable this way.")
    print()
