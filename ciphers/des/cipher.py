import random

from utils.bit_helpers import bytes_to_bits, bits_to_bytes, xor_bits


def generate_key():
    # Output: e.g. b'\xa3\xf7\x2b\x01\xc4\x5e\xd8\x80'  (8 random bytes)
    return bytes([random.randint(0, 255) for _ in range(8)])


def generate_round_keys(key_bytes, num_rounds=8):
    # Input:  b'\xa3\xf7\x2b\x01\xc4\x5e\xd8\x80', 8
    # Output: [[1,0,1,0,...], [0,1,1,0,...], ...]  (8 lists of 32 bits each)
    key_bits = bytes_to_bits(key_bytes)
    round_keys = []

    for i in range(num_rounds):
        shift = i + 1
        rotated = key_bits[shift:] + key_bits[:shift]
        round_keys.append(rotated[:32])

    return round_keys


def _feistel_f(right_half, round_key):
    # Input:  [1,0,1,0,...] (32 bits),  [0,1,0,1,...] (32 bits)
    # Output: [1,1,1,1,...] (32 bits — XOR of the two; real DES uses S-boxes here instead)
    return xor_bits(right_half, round_key)


def _feistel_encrypt_block(block_bits, round_keys):
    # Input:  [0,1,0,0,0,0,0,1,...] (64 bits),  list of 8 round keys
    # Output: [1,0,1,1,0,0,1,0,...] (64 bits, encrypted)
    left = block_bits[:32]
    right = block_bits[32:]

    for round_key in round_keys:
        f_output = _feistel_f(right, round_key)
        new_right = xor_bits(left, f_output)
        left = right
        right = new_right

    return left + right


def _feistel_decrypt_block(block_bits, round_keys):
    # Input:  [1,0,1,1,0,0,1,0,...] (64 encrypted bits),  list of 8 round keys
    # Output: [0,1,0,0,0,0,0,1,...] (64 bits, original)
    left = block_bits[:32]
    right = block_bits[32:]

    for round_key in reversed(round_keys):
        f_output = _feistel_f(left, round_key)
        prev_right = left
        prev_left = xor_bits(right, f_output)
        left = prev_left
        right = prev_right

    return left + right


def _pkcs8_pad(data):
    # Input:  b'HELLO'
    # Output: b'HELLO\x03\x03\x03'  (3 bytes added to reach length 8)
    pad_length = 8 - (len(data) % 8)
    return data + bytes([pad_length] * pad_length)


def _pkcs8_unpad(data):
    # Input:  b'HELLO\x03\x03\x03'
    # Output: b'HELLO'
    pad_length = data[-1]
    return data[:-pad_length]


def encrypt(plaintext, key_bytes):
    # Input:  "HI", b'\xa3\xf7\x2b\x01\xc4\x5e\xd8\x80'
    # Output: {'ciphertext_hex': '3A9CF1...', 'round_keys': [...], 'num_blocks': 1, 'plaintext_padded_hex': '...'}
    round_keys = generate_round_keys(key_bytes)
    pt_bytes = _pkcs8_pad(plaintext.encode('latin-1', errors='replace'))

    ciphertext = b''
    for i in range(0, len(pt_bytes), 8):
        block = pt_bytes[i : i + 8]
        block_bits = bytes_to_bits(block)
        enc_bits = _feistel_encrypt_block(block_bits, round_keys)
        ciphertext += bits_to_bytes(enc_bits)

    return {
        'ciphertext_hex': ciphertext.hex().upper(),
        'round_keys': round_keys,
        'num_blocks': len(pt_bytes) // 8,
        'plaintext_padded_hex': pt_bytes.hex().upper(),
    }


def decrypt(ciphertext_hex, key_bytes):
    # Input:  '3A9CF1...', b'\xa3\xf7\x2b\x01\xc4\x5e\xd8\x80'
    # Output: {'plaintext': 'HI', 'round_keys': [...]}
    try:
        ct_bytes = bytes.fromhex(ciphertext_hex)
    except ValueError:
        raise ValueError(f"Invalid hex string: '{ciphertext_hex}'")

    if len(ct_bytes) % 8 != 0:
        raise ValueError(
            f"Ciphertext must be a multiple of 8 bytes. Got {len(ct_bytes)} bytes."
        )

    round_keys = generate_round_keys(key_bytes)

    plaintext_bytes = b''
    for i in range(0, len(ct_bytes), 8):
        block = ct_bytes[i : i + 8]
        block_bits = bytes_to_bits(block)
        dec_bits = _feistel_decrypt_block(block_bits, round_keys)
        plaintext_bytes += bits_to_bytes(dec_bits)

    plaintext_bytes = _pkcs8_unpad(plaintext_bytes)

    return {
        'plaintext': plaintext_bytes.decode('latin-1', errors='replace'),
        'round_keys': round_keys,
    }
