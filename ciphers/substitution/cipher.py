import random
import string

# The order of letters in English from most to least common
ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"


def generate_random_key():
    # Output: e.g. "QWERTYUIOPASDFGHJKLZXCVBNM"
    letters = list(string.ascii_uppercase)
    random.shuffle(letters)
    return "".join(letters)


def encrypt(plaintext, key):
    # Input:  "HELLO", "QWERTYUIOPASDFGHJKLZXCVBNM"
    # Output: "ITSSG"
    result = ""
    for ch in plaintext.upper():
        if ch.isalpha():
            position = ord(ch) - ord('A')
            result += key[position]
        else:
            result += ch
    return result


def decrypt(ciphertext, key):
    # Input:  "ITSSG", "QWERTYUIOPASDFGHJKLZXCVBNM"
    # Output: "HELLO"
    reverse_key = [''] * 26
    for i, ch in enumerate(key):
        reverse_key[ord(ch) - ord('A')] = chr(i + ord('A'))
    return encrypt(ciphertext, reverse_key)


def frequency_analysis(ciphertext):
    # Input:  "ITSSG"
    # Output: {'freq': {'I':1,'T':1,'S':2,'G':1}, 'total': 5, 'mapping': {...}, 'guessed_plaintext': "..."}

    # Counting each letter in the ciphertext, so that we can guess which letters they might be in English
    freq = {}  
    total = 0
    for ch in ciphertext.upper():
        if ch.isalpha():
            freq[ch] = freq.get(ch, 0) + 1
            total += 1

    # Sort cipher letters from most frequent to least frequent
    freq_pairs = []
    for letter, count in freq.items():
        freq_pairs.append((count, letter))
    freq_pairs.sort(reverse=True)

    sorted_cipher_letters = []
    for count, letter in freq_pairs:
        sorted_cipher_letters.append(letter)

    # Map each cipher letter to the English letter with the same rank
    mapping = {}
    for rank, cipher_letter in enumerate(sorted_cipher_letters):
        if rank < len(ENGLISH_FREQ_ORDER):
            mapping[cipher_letter] = ENGLISH_FREQ_ORDER[rank]

    guessed_plaintext = ""
    for ch in ciphertext.upper():
        if ch.isalpha():
            guessed_plaintext += mapping.get(ch, '?')
        else:
            guessed_plaintext += ch

    return {
        'freq': freq,
        'total': total,
        'mapping': mapping,
        'guessed_plaintext': guessed_plaintext,
    }


def brute_force_attack(ciphertext):
    # Input:  "ITSSG"
    # Output: same dict as frequency_analysis() plus an extra 'attack_note' key
    result = frequency_analysis(ciphertext)
    result['attack_note'] = (
        "This is a DEMO only. True brute force requires checking 26! keys.\n"
        "  This result uses frequency analysis to make an educated guess."
    )
    return result
