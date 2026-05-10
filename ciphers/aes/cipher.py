import random

# The AES S-Box: a 256-entry lookup table used by SubBytes.
# Each input byte is replaced by the value at that index.
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

# The inverse S-Box: built automatically from SBOX.
# If SBOX[x] == y, then INV_SBOX[y] == x (used by InvSubBytes to reverse the lookup).
INV_SBOX = [0] * 256
for original_byte, substituted_byte in enumerate(SBOX):
    INV_SBOX[substituted_byte] = original_byte

# RCON table: round constants used during key expansion to make each round key unique.
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _gf_multiply(a, b):
    # Input:  0x57, 0x13
    # Output: 0xFE
    result = 0

    for _ in range(8):
        if b & 1:
            result = result ^ a

        top_bit_was_set = (a & 0x80) != 0
        a = (a << 1) & 0xFF  # keep within one byte (8 bits)

        if top_bit_was_set:
            a = a ^ 0x1B  # reduce: XOR with the AES reduction constant

        b = b >> 1

    return result


def _bytes_to_state(data):
    # Input:  b'\x00\x01\x02...\x0f'  (16 bytes)
    # Output: [[0,4,8,12], [1,5,9,13], [2,6,10,14], [3,7,11,15]]
    state = []
    for row in range(4):
        state.append([0, 0, 0, 0])
    for row in range(4):
        for col in range(4):
            state[row][col] = data[row + 4 * col]
    return state


def _state_to_bytes(state):
    # Input:  [[0,4,8,12], [1,5,9,13], [2,6,10,14], [3,7,11,15]]
    # Output: b'\x00\x01\x02...\x0f'  (reverses _bytes_to_state)
    result = []
    for col in range(4):
        for row in range(4):
            result.append(state[row][col])
    return bytes(result)


def _sub_bytes(state):
    # Input:  [[0,0,0,0], [0,0,0,0], [0,0,0,0], [0,0,0,0]]
    # Output: [[0x63,0x63,0x63,0x63], ...]   (0 maps to 0x63 in the S-Box)
    new_state = []
    for row in range(4):
        new_state.append([0, 0, 0, 0])
    for row in range(4):
        for col in range(4):
            new_state[row][col] = SBOX[state[row][col]]
    return new_state


def _inv_sub_bytes(state):
    # Input:  [[0x63,0x63,...], ...]
    # Output: [[0,0,...], ...]   (reverses _sub_bytes)
    new_state = []
    for row in range(4):
        new_state.append([0, 0, 0, 0])
    for row in range(4):
        for col in range(4):
            new_state[row][col] = INV_SBOX[state[row][col]]
    return new_state


def _shift_rows(state):
    # Input:  [[1,2,3,4], [5,6,7,8], [9,10,11,12], [13,14,15,16]]
    # Output: [[1,2,3,4], [6,7,8,5], [11,12,9,10], [16,13,14,15]]
    new_state = []
    for row_num in range(4):
        row = []
        for col in range(4):
            row.append(state[row_num][(col + row_num) % 4])
        new_state.append(row)
    return new_state


def _inv_shift_rows(state):
    # Input:  [[1,2,3,4], [6,7,8,5], [11,12,9,10], [16,13,14,15]]
    # Output: [[1,2,3,4], [5,6,7,8], [9,10,11,12], [13,14,15,16]]
    new_state = []
    for row_num in range(4):
        row = []
        for col in range(4):
            row.append(state[row_num][(col - row_num) % 4])
        new_state.append(row)
    return new_state


def _mix_columns(state):
    # Input:  [[1,0,0,0], [0,1,0,0], [0,0,1,0], [0,0,0,1]]  (identity-like state)
    # Output: each column transformed by the MixColumns matrix
    new_state = []
    for row in range(4):
        new_state.append([0, 0, 0, 0])

    for col in range(4):
        c0 = state[0][col]
        c1 = state[1][col]
        c2 = state[2][col]
        c3 = state[3][col]

        c0_x2 = _gf_multiply(2, c0);  c0_x3 = _gf_multiply(3, c0)
        c1_x2 = _gf_multiply(2, c1);  c1_x3 = _gf_multiply(3, c1)
        c2_x2 = _gf_multiply(2, c2);  c2_x3 = _gf_multiply(3, c2)
        c3_x2 = _gf_multiply(2, c3);  c3_x3 = _gf_multiply(3, c3)

        new_state[0][col] = c0_x2 ^ c1_x3 ^ c2    ^ c3
        new_state[1][col] = c0    ^ c1_x2 ^ c2_x3 ^ c3
        new_state[2][col] = c0    ^ c1    ^ c2_x2 ^ c3_x3
        new_state[3][col] = c0_x3 ^ c1    ^ c2    ^ c3_x2

    return new_state


def _inv_mix_columns(state):
    # Input:  output of _mix_columns
    # Output: the original state before mixing (reverses _mix_columns)
    new_state = []
    for row in range(4):
        new_state.append([0, 0, 0, 0])

    for col in range(4):
        c0 = state[0][col]
        c1 = state[1][col]
        c2 = state[2][col]
        c3 = state[3][col]

        c0_x14 = _gf_multiply(14, c0);  c0_x9  = _gf_multiply(9,  c0)
        c0_x13 = _gf_multiply(13, c0);  c0_x11 = _gf_multiply(11, c0)
        c1_x14 = _gf_multiply(14, c1);  c1_x9  = _gf_multiply(9,  c1)
        c1_x13 = _gf_multiply(13, c1);  c1_x11 = _gf_multiply(11, c1)
        c2_x14 = _gf_multiply(14, c2);  c2_x9  = _gf_multiply(9,  c2)
        c2_x13 = _gf_multiply(13, c2);  c2_x11 = _gf_multiply(11, c2)
        c3_x14 = _gf_multiply(14, c3);  c3_x9  = _gf_multiply(9,  c3)
        c3_x13 = _gf_multiply(13, c3);  c3_x11 = _gf_multiply(11, c3)

        new_state[0][col] = c0_x14 ^ c1_x11 ^ c2_x13 ^ c3_x9
        new_state[1][col] = c0_x9  ^ c1_x14 ^ c2_x11 ^ c3_x13
        new_state[2][col] = c0_x13 ^ c1_x9  ^ c2_x14 ^ c3_x11
        new_state[3][col] = c0_x11 ^ c1_x13 ^ c2_x9  ^ c3_x14

    return new_state


def _add_round_key(state, round_key):
    # Input:  [[0,0,0,0],...],  [[1,1,1,1],...]
    # Output: [[1,1,1,1],...]   (0 XOR 1 = 1 for each byte)
    new_state = []
    for row in range(4):
        new_state.append([0, 0, 0, 0])
    for row in range(4):
        for col in range(4):
            new_state[row][col] = state[row][col] ^ round_key[row][col]
    return new_state


def key_expansion(key_bytes):
    # Input:  b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'  (16 bytes)
    # Output: [[[43,126,...], ...], [[...], ...], ...]   (11 round key matrices for AES-128)
    key_len = len(key_bytes)
    if key_len not in (16, 24, 32):
        raise ValueError(f"AES key must be 16, 24, or 32 bytes. Got {key_len}.")

    nk = key_len // 4          # number of 4-byte words in the key (4, 6, or 8)
    nr = 6 + nk                # total rounds (10, 12, or 14)
    total_words = 4 * (nr + 1) # total 4-byte words needed across all round keys

    # Load the original key bytes as the first nk words
    words = []
    for i in range(nk):
        words.append(list(key_bytes[i * 4 : (i + 1) * 4]))

    # Generate the remaining words one at a time
    for i in range(nk, total_words):
        temp = words[i - 1][:]  # start with a copy of the previous word

        if i % nk == 0:
            # Every nk words: rotate, substitute through SBOX, then XOR with RCON
            temp = temp[1:] + temp[:1]       # RotWord: rotate left by one byte

            subbed = []                      # SubWord: replace each byte via SBOX
            for byte in temp:
                subbed.append(SBOX[byte])
            temp = subbed

            temp[0] = temp[0] ^ RCON[(i // nk) - 1]  # add the round constant

        elif nk == 8 and i % nk == 4:
            # AES-256 only: extra SubWord at the midpoint of each group of 8
            subbed = []
            for byte in temp:
                subbed.append(SBOX[byte])
            temp = subbed

        # XOR with the word that is nk positions back
        new_word = []
        for j in range(4):
            new_word.append(words[i - nk][j] ^ temp[j])
        words.append(new_word)

    # Pack words into (nr+1) round key matrices, each 4x4, column-major
    round_keys = []
    for rk_num in range(nr + 1):
        rk_words = words[rk_num * 4 : (rk_num + 1) * 4]
        rk_matrix = []
        for _ in range(4):
            rk_matrix.append([0, 0, 0, 0])
        for col in range(4):
            for row in range(4):
                rk_matrix[row][col] = rk_words[col][row]
        round_keys.append(rk_matrix)

    return round_keys


def _pkcs7_pad(data, block_size=16):
    # Input:  b'HELLO', 16
    # Output: b'HELLO\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'  (11 padding bytes added)
    pad_length = block_size - (len(data) % block_size)
    return data + bytes([pad_length] * pad_length)


def _pkcs7_unpad(data):
    # Input:  b'HELLO\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'
    # Output: b'HELLO'
    pad_length = data[-1]
    return data[:-pad_length]


def _encrypt_block(block_bytes, round_keys, nr):
    # Input:  b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34', round_keys, 10
    # Output: b'\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32'  (NIST test vector)
    state = _bytes_to_state(block_bytes)
    state = _add_round_key(state, round_keys[0])

    for round_num in range(1, nr):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[round_num])

    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[nr])

    return _state_to_bytes(state)


def _decrypt_block(block_bytes, round_keys, nr):
    # Input:  b'\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32', round_keys, 10
    # Output: b'\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34'  (reverses _encrypt_block)
    state = _bytes_to_state(block_bytes)
    state = _add_round_key(state, round_keys[nr])

    for round_num in range(nr - 1, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[round_num])
        state = _inv_mix_columns(state)

    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])

    return _state_to_bytes(state)


# Map from key size in bits to key length in bytes
_KEY_SIZE_BYTES = {128: 16, 192: 24, 256: 32}


def generate_key(key_size=128):
    # Input:  128
    # Output: e.g. b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'  (16 random bytes)
    if key_size not in _KEY_SIZE_BYTES:
        raise ValueError(f"key_size must be 128, 192, or 256. Got {key_size}.")
    key_bytes = []
    for _ in range(_KEY_SIZE_BYTES[key_size]):
        key_bytes.append(random.randint(0, 255))
    return bytes(key_bytes)


def encrypt(plaintext, key_bytes):
    # Input:  "HELLO", b'\x2b\x7e...'  (16-byte key)
    # Output: {'ciphertext_hex': '8F3A...', 'ciphertext_bytes': b'...', 'num_blocks': 1, 'variant': 'AES-128', ...}
    round_keys = key_expansion(key_bytes)
    nk = len(key_bytes) // 4
    nr = 6 + nk
    variant = f"AES-{len(key_bytes) * 8}"

    pt_bytes = _pkcs7_pad(plaintext.encode('utf-8'))

    ciphertext = b''
    for i in range(0, len(pt_bytes), 16):
        block = pt_bytes[i : i + 16]
        ciphertext += _encrypt_block(block, round_keys, nr)

    return {
        'ciphertext_bytes': ciphertext,
        'ciphertext_hex': ciphertext.hex().upper(),
        'round_keys': round_keys,
        'num_blocks': len(pt_bytes) // 16,
        'variant': variant,
    }


def decrypt(ciphertext_hex, key_bytes):
    # Input:  '8F3A...', b'\x2b\x7e...'  (same key used to encrypt)
    # Output: {'plaintext': 'HELLO', 'variant': 'AES-128', 'round_keys': [...]}
    try:
        ct_bytes = bytes.fromhex(ciphertext_hex)
    except ValueError:
        raise ValueError(f"Invalid hex string: '{ciphertext_hex}'")

    if len(ct_bytes) % 16 != 0:
        raise ValueError(f"Ciphertext length must be a multiple of 16 bytes. Got {len(ct_bytes)}.")

    round_keys = key_expansion(key_bytes)
    nk = len(key_bytes) // 4
    nr = 6 + nk
    variant = f"AES-{len(key_bytes) * 8}"

    plaintext_bytes = b''
    for i in range(0, len(ct_bytes), 16):
        block = ct_bytes[i : i + 16]
        plaintext_bytes += _decrypt_block(block, round_keys, nr)

    plaintext_bytes = _pkcs7_unpad(plaintext_bytes)

    return {
        'plaintext': plaintext_bytes.decode('utf-8'),
        'round_keys': round_keys,
        'variant': variant,
    }
