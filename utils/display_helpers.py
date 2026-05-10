def print_separator(title=""):
    # Input:  "DES Cipher"
    # Output: prints  ==...==  / "  DES Cipher" / ==...==  to the terminal
    line = "=" * 50
    if title:
        print(f"\n{line}")
        print(f"  {title}")
        print(line)
    else:
        print(line)


def get_letter_frequencies(text):
    # Input:  "HELLO"
    # Output: ({'H':1, 'E':1, 'L':2, 'O':1}, 5)
    freq = {}
    total = 0
    for ch in text.upper():
        if ch.isalpha():
            freq[ch] = freq.get(ch, 0) + 1
            total += 1
    return freq, total


def print_freq_chart(freq_dict, total):
    # Input:  {'A': 5, 'B': 3}, 8
    # Output: prints a bar chart to the terminal (top 10 letters by frequency)
    print("\n  Letter Frequency Analysis:")
    print("  " + "-" * 40)

    if total == 0:
        print("  (No letters found in text.)")
        return

    # Build a list of (count, letter) pairs 
    freq_pairs = []
    for letter, count in freq_dict.items():
        freq_pairs.append((count, letter))
    freq_pairs.sort(reverse=True)

    # Rebuild as (letter, count) for display
    sorted_letters = []
    for count, letter in freq_pairs:
        sorted_letters.append((letter, count))

    for letter, count in sorted_letters[:10]:
        percent = (count / total) * 100
        bar_length = int(percent * 2)
        bar = '█' * bar_length
        print(f"  {letter}: {bar:<20} {percent:.1f}%")
