# ciphers/des/cipher.py

import random

from utils.bit_helpers import bytes_to_bits, bits_to_bytes, xor_bits

# Initial Permutation (IP): reorders the 64 input bits before the 16 rounds.
# Applied once at the very start of encryption.
IP = [
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
]

# Final Permutation (FP = IP^-1): applied after all 16 rounds. Undoes the IP.
FP = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
]

# PC-1 (Permuted Choice 1): selects 56 bits from the 64-bit key.
# A DES key is 64 bits total, but every 8th bit (positions 8,16,24,...,64)
# is a parity bit and carries no key information. PC-1 drops all 8 parity bits
PC1 = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
]

# PC-2 (Permuted Choice 2): selects 48 bits from the 56-bit shifted key halves.
# Each of the 16 rounds calls PC-2 once to produce that round's 48-bit round key.
PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

# Left-shift schedule: how many bits to rotate each key half in each round.
# Rounds 1, 2, 9, 16 rotate by 1; all other rounds rotate by 2.
LEFT_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# Expansion table (E): expands the 32-bit right half to 48 bits.
# Some bits are repeated so the result can be XOR-ed with the 48-bit round key.
E = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
]

# P-box: 32-bit permutation applied to the 32-bit output of the 8 S-boxes.
P = [
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25,
]

# 8 S-boxes
SBOXES = [
    # S1
    [[14, 4, 13, 1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
     [ 0, 15, 7, 4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
     [ 4,  1,14, 8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
     [15, 12, 8, 2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]],
    # S2
    [[15,  1, 8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
     [ 3, 13, 4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
     [ 0, 14, 7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
     [13,  8,10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]],
    # S3
    [[10,  0, 9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
     [13,  7, 0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
     [13,  6, 4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
     [ 1, 10,13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]],
    # S4
    [[ 7, 13,14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
     [13,  8,11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
     [10,  6, 9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
     [ 3, 15, 0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]],
    # S5
    [[ 2, 12, 4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
     [14, 11, 2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
     [ 4,  2, 1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
     [11,  8,12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]],
    # S6
    [[12,  1,10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
     [10, 15, 4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
     [ 9, 14,15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
     [ 4,  3, 2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]],
    # S7
    [[ 4, 11, 2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
     [13,  0,11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
     [ 1,  4,11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
     [ 6, 11,13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]],
    # S8
    [[13,  2, 8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
     [ 1, 15,13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
     [ 7, 11, 4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
     [ 2,  1,14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]],
]

def _permute(bits, table):
    return [bits[pos - 1] for pos in table]


def _left_rotate(bits, n):
    # Input:  [1,0,1,0,...], shift amount n
    # Output: bits rotated left 
    return bits[n:] + bits[:n]


def _sbox_lookup(six_bits, sbox):
    # Input:  6-bit list [b0,b1,b2,b3,b4,b5]
    # Output: 4-bit list
    row = six_bits[0] * 2 + six_bits[5]
    col = six_bits[1] * 8 + six_bits[2] * 4 + six_bits[3] * 2 + six_bits[4]
    value = sbox[row][col]
    # Convert the integer result (0–15) back to a 4-bit list
    return [(value >> (3 - i)) & 1 for i in range(4)]


def generate_key():
    return bytes(random.randint(0, 255) for _ in range(8))


def generate_round_keys(key_bytes):

    if len(key_bytes) != 8:
        raise ValueError(f"DES key must be exactly 8 bytes. Got {len(key_bytes)}.")

    key_bits = bytes_to_bits(key_bytes)          # 8 bytes → 64-bit list

    # Step 1: PC-1 removes the 8 parity bits (64 bits → 56 bits)
    key_56 = _permute(key_bits, PC1)

    # Step 2: Split into two 28-bit halves
    C = key_56[:28]
    D = key_56[28:]

    round_keys = []

    for i in range(16):
        C = _left_rotate(C, LEFT_SHIFTS[i])
        D = _left_rotate(D, LEFT_SHIFTS[i])

        round_key = _permute(C + D, PC2)
        round_keys.append(round_key)

    return round_keys                           


def _feistel_f(right_32, round_key_48):

    # Step 1: Expand 32 → 48 bits
    expanded = _permute(right_32, E)

    # Step 2: XOR with the round key
    xored = xor_bits(expanded, round_key_48)

    # Step 3: Eight S-boxes in parallel (48 bits → 32 bits)
    sbox_output = []
    for i in range(8):
        six_bits = xored[i * 6 : (i + 1) * 6]          # take 6 bits for S-box i
        sbox_output += _sbox_lookup(six_bits, SBOXES[i])  # get 4 bits back

    # Step 4: P-box permutation
    return _permute(sbox_output, P)


def _feistel_encrypt_block(block_bits, round_keys):
    # Step 1: Initial Permutation
    bits  = _permute(block_bits, IP)

    # Step 2: Split
    left  = bits[:32]
    right = bits[32:]

    # Step 3: 16 Feistel rounds
    for i in range(16):
        new_left  = right
        new_right = xor_bits(left, _feistel_f(right, round_keys[i]))
        left  = new_left
        right = new_right

    # Step 4 + 5: Swap halves, then apply Final Permutation
    return _permute(right + left, FP)


def _feistel_decrypt_block(block_bits, round_keys):
    return _feistel_encrypt_block(block_bits, list(reversed(round_keys)))


def _pkcs7_pad(data):
    # Input:  b'HELLO'  (5 bytes)
    # Output: b'HELLO\x03\x03\x03'
    pad_length = 8 - (len(data) % 8)
    return data + bytes([pad_length] * pad_length)


def _pkcs7_unpad(data):
    # Input:  padded bytes
    # Output: original bytes
    return data[:-data[-1]]


def encrypt(plaintext, key_bytes):
    # Input:  "HELLO WORLD",  8-byte key
    # Output: dict with 'ciphertext_hex', 'round_keys', 'num_blocks', 'plaintext_padded_hex'
    if len(key_bytes) != 8:
        raise ValueError(f"DES key must be exactly 8 bytes. Got {len(key_bytes)}.")

    round_keys = generate_round_keys(key_bytes)
    pt_bytes   = _pkcs7_pad(plaintext.encode('latin-1', errors='replace'))

    ciphertext = b''
    for i in range(0, len(pt_bytes), 8):
        block_bits  = bytes_to_bits(pt_bytes[i : i + 8])        
        enc_bits    = _feistel_encrypt_block(block_bits, round_keys)
        ciphertext += bits_to_bytes(enc_bits)   

    return {
        'ciphertext_hex':       ciphertext.hex().upper(),
        'round_keys':           round_keys,
        'num_blocks':           len(pt_bytes) // 8,
        'plaintext_padded_hex': pt_bytes.hex().upper(),
    }


def decrypt(ciphertext_hex, key_bytes):
    try:
        ct_bytes = bytes.fromhex(ciphertext_hex)
    except ValueError:
        raise ValueError(f"Invalid hex string: '{ciphertext_hex}'")

    if len(ct_bytes) % 8 != 0:
        raise ValueError(f"Ciphertext must be a multiple of 8 bytes. Got {len(ct_bytes)} bytes.")

    if len(key_bytes) != 8:
        raise ValueError(f"DES key must be exactly 8 bytes. Got {len(key_bytes)}.")

    round_keys = generate_round_keys(key_bytes)

    pt_bytes = b''
    for i in range(0, len(ct_bytes), 8):
        block_bits  = bytes_to_bits(ct_bytes[i : i + 8])
        dec_bits    = _feistel_decrypt_block(block_bits, round_keys)
        pt_bytes   += bits_to_bytes(dec_bits)

    return {
        'plaintext':  _pkcs7_unpad(pt_bytes).decode('latin-1', errors='replace'),
        'round_keys': round_keys,
    }
