import random
import math

from utils.bit_helpers import mod_inverse, mod_pow, int_to_bytes, bytes_to_int

def _miller_rabin(n, rounds=10):
    # Input:  17, 10
    # Output: True   (17 is prime)
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # split n-1 into 2^r * d where d is odd
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = mod_pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        this_witness_passed = False
        for _ in range(r - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                this_witness_passed = True
                break

        if not this_witness_passed:
            return False

    return True

def _generate_prime(bits):
    # Input:  16
    # Output: e.g. 54217  (a random prime of exactly 16 bits)
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) 
        candidate |= 1 
        if _miller_rabin(candidate):
            return candidate

def generate_keys(bits=256):
    # Input:  prime size in bits (e.g. 256 → ~512-bit key, 512 → ~1024-bit key)
    # Output: e.g. {'e': 65537, 'd': 34891..., 'n': 70023..., 'p': 76847..., 'q': 91205..., 'phi': ..., 'key_bits': 512}
    p = _generate_prime(bits)
    q = _generate_prime(bits)
    while q == p:
        q = _generate_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while math.gcd(e, phi) != 1:
        e += 2 

    d = mod_inverse(e, phi)

    return {
        'e': e,
        'd': d,
        'n': n,
        'p': p,
        'q': q,
        'phi': phi,
        'key_bits': bits * 2,
    }

def _chunk_size(n):
    # Input:  n = 2847361917  (32-bit modulus)
    # Output: 3   (can encrypt 3 bytes per chunk)
    return (n.bit_length() // 8) - 1

def encrypt(message_str, e, n):
    # Input:  "HI", 65537, 2847361917
    # Output: {'chunks': [1876543, 2341098], 'num_chunks': 2, 'chunk_size_bytes': 3}
    message_bytes = message_str.encode('utf-8')
    chunk_size = _chunk_size(n)

    if chunk_size < 1:
        raise ValueError("RSA key is too small to encrypt any data. Generate a larger key.")

    ciphertext_chunks = []
    for i in range(0, len(message_bytes), chunk_size):
        chunk_bytes = message_bytes[i : i + chunk_size]
        m = bytes_to_int(chunk_bytes)
        c = mod_pow(m, e, n)
        ciphertext_chunks.append(c)

    return {
        'chunks': ciphertext_chunks,
        'num_chunks': len(ciphertext_chunks),
        'chunk_size_bytes': chunk_size,
    }

def decrypt(ciphertext_chunks, d, n):
    # Input:  [1876543, 2341098], 1928374650, 2847361917
    # Output: "HI"
    recovered_bytes = b''
    for c in ciphertext_chunks:
        m = mod_pow(c, d, n)
        recovered_bytes += int_to_bytes(m)
    return recovered_bytes.decode('utf-8')

def encrypt_trace(plaintext, e, n, d=None, p=None, q=None, phi=None):
    # Input:  "HI", 65537, big_n  (optionally d, p, q, phi for full key trace)
    # Output: dict with 'steps' showing key structure + first chunk encrypt/decrypt
    steps = []
    if p and q and phi:
        steps.append({
            "name":   "Key Structure",
            "desc":   "RSA keys are derived from two large primes p and q.",
            "phase":  "keygen",
            "values": [
                ("p  (prime)", str(p)),
                ("q  (prime)", str(q)),
                ("n = p × q", str(n)),
                ("φ(n) = (p−1)(q−1)", str(phi)),
                ("e  (public exponent)", str(e)),
                ("d  (private exponent)", str(d) if d else "unknown"),
            ],
        })
    else:
        steps.append({
            "name":   "Public Key",
            "desc":   "RSA public key (e, n). Private key d is not shown.",
            "phase":  "keygen",
            "values": [
                ("n (modulus)", str(n)),
                ("e (public exponent)", str(e)),
            ],
        })
    chunk_size  = max(1, _chunk_size(n))
    first_bytes = plaintext.encode('utf-8')[:chunk_size]
    m = bytes_to_int(first_bytes)
    steps.append({
        "name":   "Convert Text → Integer (m)",
        "desc":   f"First {len(first_bytes)} byte(s) read as a big-endian integer.",
        "phase":  "convert",
        "values": [
            ("chunk text", first_bytes.decode('latin-1', errors='replace')),
            ("bytes (hex)", ' '.join(f'{b:02X}' for b in first_bytes)),
            ("m (integer)", str(m)),
        ],
    })
    c = mod_pow(m, e, n)
    steps.append({
        "name":   "Encrypt:  c = mᵉ mod n",
        "desc":   "Modular exponentiation with the public key. Anyone with (e, n) can encrypt.",
        "phase":  "encrypt",
        "values": [
            ("m", str(m)),
            ("e", str(e)),
            ("n", str(n)),
            ("c = mᵉ mod n", str(c)),
        ],
    })
    if d:
        m_rec = mod_pow(c, d, n)
        steps.append({
            "name":   "Decrypt:  m = cᵈ mod n",
            "desc":   "Only the holder of private key d can reverse the encryption.",
            "phase":  "decrypt",
            "values": [
                ("c", str(c)),
                ("d", str(d)),
                ("n", str(n)),
                ("m = cᵈ mod n", str(m_rec)),
                ("matches original?", str(m_rec == m)),
            ],
        })

    return {"steps": steps, "num_steps": len(steps)}

def _pollard_rho(n):
    # Input:  2847361917
    # Output: 49871  (one of the prime factors, or None if this attempt failed)
    if n % 2 == 0:
        return 2

    x = random.randint(2, n - 1)
    y = x
    c = random.randint(1, n - 1)
    d = 1

    while d == 1:
        x = (x * x + c) % n       
        y = (y * y + c) % n      
        y = (y * y + c) % n
        d = math.gcd(abs(x - y), n)

    if d != n:
        return d
    return None

def factorization_attack(n, e, max_attempts=30):
    # Input:  2847361917, 65537, 30
    # Output: {'success': True, 'p': 49871, 'q': 57107, 'd_recovered': 1928374650, 'attempts': 3, 'note': '...'}
    note = (
        "Pollard's Rho demo — only works on small n (around 32-64 bits).\n"
        "  Real 512-bit+ RSA keys cannot be factored this way."
    )

    for attempt in range(1, max_attempts + 1):
        factor = _pollard_rho(n)
        if factor and 1 < factor < n:
            p_found = factor
            q_found = n // factor
            phi_found = (p_found - 1) * (q_found - 1)
            try:
                d_recovered = mod_inverse(e, phi_found)
            except ValueError:
                continue

            return {
                'success': True,
                'p': p_found,
                'q': q_found,
                'd_recovered': d_recovered,
                'attempts': attempt,
                'note': note,
            }

    return {
        'success': False,
        'p': None,
        'q': None,
        'd_recovered': None,
        'attempts': max_attempts,
        'note': note,
    }
