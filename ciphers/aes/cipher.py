import random

# AES S-Box: 256-entry substitution table — each byte is replaced by the value at its index
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

# Inverse S-Box: reverses SBOX — built automatically so INV_SBOX[SBOX[x]] == x
INV_SBOX = [0] * 256
for _i, _s in enumerate(SBOX):
    INV_SBOX[_s] = _i

# Round constants 
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _gf_multiply(a, b):
    # Input:  0x57, 0x13
    # Output: 0xFE
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF     
        if high_bit:
            a ^= 0x1B     
        b >>= 1
    return result


def _bytes_to_state(data):
    # Input:  b'\x00\x01\x02...\x0f'  (16 bytes)
    # Output: 4x4 grid filled column by column: state[row][col] = data[row + 4*col]
    state = [[0] * 4 for _ in range(4)]
    for row in range(4):
        for col in range(4):
            state[row][col] = data[row + 4 * col]
    return state


def _state_to_bytes(state):
    # Input:  4x4 state matrix
    # Output: 16 bytes read back column by column
    result = []
    for col in range(4):
        for row in range(4):
            result.append(state[row][col])
    return bytes(result)


def _sub_bytes(state):
    # Input:  [[0,0,...], ...]   (any 4x4 state)
    # Output: every byte replaced by SBOX[byte]
    return [[SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def _inv_sub_bytes(state):
    # Input:  state after SubBytes
    # Output: original state restored using the inverse S-Box
    return [[INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]


def _shift_rows(state):
    # Input:  [[1,2,3,4], [5,6,7,8], [9,10,11,12], [13,14,15,16]]
    # Output: [[1,2,3,4], [6,7,8,5], [11,12,9,10], [16,13,14,15]]
    return [[state[r][(c + r) % 4] for c in range(4)] for r in range(4)]


def _inv_shift_rows(state):
    # Input:  shifted state
    # Output: original state (shifts each row right by its row index)
    return [[state[r][(c - r) % 4] for c in range(4)] for r in range(4)]


def _mix_columns(state):
    # Input:  any 4x4 state
    # Output: each column mixed using the AES matrix over GF(2^8)
    new_state = [[0] * 4 for _ in range(4)]
    for col in range(4):
        s = [state[r][col] for r in range(4)]
        new_state[0][col] = _gf_multiply(2, s[0]) ^ _gf_multiply(3, s[1]) ^ s[2]                    ^ s[3]
        new_state[1][col] = s[0]                   ^ _gf_multiply(2, s[1]) ^ _gf_multiply(3, s[2]) ^ s[3]
        new_state[2][col] = s[0]                   ^ s[1]                   ^ _gf_multiply(2, s[2]) ^ _gf_multiply(3, s[3])
        new_state[3][col] = _gf_multiply(3, s[0]) ^ s[1]                   ^ s[2]                   ^ _gf_multiply(2, s[3])
    return new_state


def _inv_mix_columns(state):
    # Input:  state after MixColumns
    # Output: original column values restored using the inverse AES matrix
    new_state = [[0] * 4 for _ in range(4)]
    for col in range(4):
        s = [state[r][col] for r in range(4)]
        new_state[0][col] = _gf_multiply(14, s[0]) ^ _gf_multiply(11, s[1]) ^ _gf_multiply(13, s[2]) ^ _gf_multiply(9,  s[3])
        new_state[1][col] = _gf_multiply(9,  s[0]) ^ _gf_multiply(14, s[1]) ^ _gf_multiply(11, s[2]) ^ _gf_multiply(13, s[3])
        new_state[2][col] = _gf_multiply(13, s[0]) ^ _gf_multiply(9,  s[1]) ^ _gf_multiply(14, s[2]) ^ _gf_multiply(11, s[3])
        new_state[3][col] = _gf_multiply(11, s[0]) ^ _gf_multiply(13, s[1]) ^ _gf_multiply(9,  s[2]) ^ _gf_multiply(14, s[3])
    return new_state


def _add_round_key(state, round_key):
    # Input:  state, round_key  (both 4x4 matrices)
    # Output: state XOR round_key, byte by byte — mixes the secret key into the data
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]


def key_expansion(key_bytes):
    # Input:  16/24/32-byte key
    # Output: list of (nr+1) round key matrices — one per AES round
    key_len = len(key_bytes)
    if key_len not in (16, 24, 32):
        raise ValueError(f"AES key must be 16, 24, or 32 bytes. Got {key_len}.")

    nk = key_len // 4           # words in the key: 4 (AES-128), 6 (192), 8 (256)
    nr = 6 + nk                 # total rounds:    10 (AES-128), 12 (192), 14 (256)
    total_words = 4 * (nr + 1)

    words = [list(key_bytes[i * 4:(i + 1) * 4]) for i in range(nk)]

    for i in range(nk, total_words):
        temp = words[i - 1][:]

        if i % nk == 0:
            temp = temp[1:] + temp[:1]          # RotWord: rotate left by one byte
            temp = [SBOX[b] for b in temp]      # SubWord: substitute each byte via S-Box
            temp[0] ^= RCON[(i // nk) - 1]     # XOR with round constant
        elif nk == 8 and i % nk == 4:
            temp = [SBOX[b] for b in temp]      # AES-256 only: extra SubWord at midpoint

        words.append([words[i - nk][j] ^ temp[j] for j in range(4)])

    # every 4 words into a column-major 4x4 round key matrix
    round_keys = []
    for rk_num in range(nr + 1):
        rk_words = words[rk_num * 4:(rk_num + 1) * 4]
        rk_matrix = [[rk_words[col][row] for col in range(4)] for row in range(4)]
        round_keys.append(rk_matrix)

    return round_keys


def _pkcs7_pad(data, block_size=16):
    # Input:  b'HELLO', 16
    # Output: b'HELLO' + 11 bytes of value 0x0B 
    pad_length = block_size - (len(data) % block_size)
    return data + bytes([pad_length] * pad_length)


def _pkcs7_unpad(data):
    # Input:  padded bytes
    # Output: original bytes with padding removed 
    return data[:-data[-1]]


def _encrypt_block(block_bytes, round_keys, nr):
    # Input:  16-byte block, expanded round keys, number of rounds
    # Output: 16-byte encrypted block
    state = _bytes_to_state(block_bytes)
    state = _add_round_key(state, round_keys[0])    

    for i in range(1, nr):                 
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[i])

    # Final round: same as above but no MixColumns
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[nr])
    return _state_to_bytes(state)


def _decrypt_block(block_bytes, round_keys, nr):
    # Input:  16-byte encrypted block, same round keys, same nr
    # Output: original 16-byte plaintext block
    state = _bytes_to_state(block_bytes)
    state = _add_round_key(state, round_keys[nr])  

    for i in range(nr - 1, 0, -1):     
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, round_keys[i])
        state = _inv_mix_columns(state)

    # Undo the initial round 
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, round_keys[0])
    return _state_to_bytes(state)


# Maps key size in bits → key length in bytes
_KEY_SIZE_BYTES = {128: 16, 192: 24, 256: 32}


def generate_key(key_size=128):
    # Input:  128, 192, or 256
    # Output: random bytes of the matching length 
    if key_size not in _KEY_SIZE_BYTES:
        raise ValueError(f"key_size must be 128, 192, or 256. Got {key_size}.")
    return bytes(random.randint(0, 255) for _ in range(_KEY_SIZE_BYTES[key_size]))


def encrypt(plaintext, key_bytes):
    # Input:  "HELLO WORLD", 16-byte key
    # Output: dict with 'ciphertext_hex', 'ciphertext_bytes', 'round_keys', 'num_blocks', 'variant'
    round_keys = key_expansion(key_bytes)
    nk = len(key_bytes) // 4
    nr = 6 + nk
    variant = f"AES-{len(key_bytes) * 8}"

    pt_bytes = _pkcs7_pad(plaintext.encode('utf-8'))
    ciphertext = b''.join(
        _encrypt_block(pt_bytes[i:i + 16], round_keys, nr)
        for i in range(0, len(pt_bytes), 16)
    )

    return {
        'ciphertext_bytes': ciphertext,
        'ciphertext_hex':   ciphertext.hex().upper(),
        'round_keys':       round_keys,
        'num_blocks':       len(pt_bytes) // 16,
        'variant':          variant,
    }


def decrypt(ciphertext_hex, key_bytes):
    # Input:  hex string from encrypt(), same key bytes
    # Output: dict with 'plaintext', 'round_keys', 'variant'
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

    pt_bytes = b''.join(
        _decrypt_block(ct_bytes[i:i + 16], round_keys, nr)
        for i in range(0, len(ct_bytes), 16)
    )

    return {
        'plaintext':  _pkcs7_unpad(pt_bytes).decode('utf-8'),
        'round_keys': round_keys,
        'variant':    variant,
    }
