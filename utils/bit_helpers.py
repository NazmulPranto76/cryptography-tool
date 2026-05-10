def bytes_to_bits(b):
    # Input:  b'\xa3'
    # Output: [1, 0, 1, 0, 0, 0, 1, 1]
    bits = []
    for byte in b:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits):
    # Input:  [1, 0, 1, 0, 0, 0, 1, 1]
    # Output: b'\xa3'
    while len(bits) % 8 != 0:
        bits = [0] + bits

    result = []
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i + 8]:
            byte = (byte << 1) | bit
        result.append(byte)
    return bytes(result)


def xor_bits(a, b):
    # Input:  [1, 0, 1],  [1, 1, 0]
    # Output: [0, 1, 1]
    result = []
    for x, y in zip(a, b):
        result.append(x ^ y)
    return result


def extended_gcd(a, b):
    # Input:  35, 15
    # Output: (5, 1, -2)   →   35*1 + 15*(-2) = 5
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = extended_gcd(b, a % b)
    return gcd, y1, x1 - (a // b) * y1


def mod_inverse(e, phi):
    # Input:  3, 10
    # Output: 7   →   (3 * 7) % 10 == 1
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist (gcd={gcd}, not 1).")
    return x % phi


def mod_pow(base, exp, mod):
    # Input:  2, 10, 1000
    # Output: 24   →   (2 ** 10) % 1000 == 24
    return pow(base, exp, mod)


def int_to_bytes(n):
    # Input:  255
    # Output: b'\xff'
    if n == 0:
        return b'\x00'
    byte_length = (n.bit_length() + 7) // 8
    return n.to_bytes(byte_length, 'big')


def bytes_to_int(b):
    # Input:  b'\xff'
    # Output: 255
    return int.from_bytes(b, 'big')
