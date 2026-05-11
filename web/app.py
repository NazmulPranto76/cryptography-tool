# web/app.py — FastAPI REST API 
# Run: uvicorn app:app --reload   (from inside the web/ folder)
import sys
import os
import time
import math

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Optional, List

from utils.bit_helpers import mod_inverse

from ciphers.substitution  import cipher as sub
from ciphers.double_transposition import cipher as dt
from ciphers.des           import cipher as des
from ciphers.aes           import cipher as aes
from ciphers.rsa           import cipher as rsa
from ciphers.ecc           import cipher as ecc

from analysis.timing      import run_timing_analysis
from analysis.brute_force import run_brute_force

app = FastAPI(title="Cryptography Tool", version="1.0")

app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")


@app.get("/")
def serve_ui():
    """Serve the single-page app."""
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))


class SubEncryptRequest(BaseModel):
    plaintext: str
    key: Optional[str] = None   

class SubDecryptRequest(BaseModel):
    ciphertext: str
    key: str

class SubAnalyzeRequest(BaseModel):
    ciphertext: str

class TranspositionRequest(BaseModel):
    text: str
    key1: str = Field(example="3 1 4 2")
    key2: str = Field(example="2 4 1 3")

class TranspositionDecryptRequest(BaseModel):
    ciphertext: str
    key1: str
    key2: str

class DESRequest(BaseModel):
    plaintext: str
    key_hex: Optional[str] = None  

class DESDecryptRequest(BaseModel):
    ciphertext_hex: str
    key_hex: str

class AESRequest(BaseModel):
    plaintext: str
    key_size: int = 128         
    key_hex: Optional[str] = None  

class AESDecryptRequest(BaseModel):
    ciphertext_hex: str
    key_hex: str

class RSAGenerateRequest(BaseModel):
    key_bits: int = 512
    custom_e: Optional[str] = None   # optional public exponent (default 65537)
    custom_p: Optional[str] = None   # optional prime p
    custom_q: Optional[str] = None   # optional prime q


class RSAEncryptRequest(BaseModel):
    plaintext: str
    e: str
    n: str


class RSADecryptRequest(BaseModel):
    chunks: list[str]
    d: str
    n: str


class RSAAttackRequest(BaseModel):
    n: str
    e: str

# class RSAGenerateRequest(BaseModel):
#     key_bits: int = 512            

# class RSAEncryptRequest(BaseModel):
#     plaintext: str
#     e: int
#     n: int

# class RSADecryptRequest(BaseModel):
#     chunks: List[int]
#     d: int
#     n: int

# class RSAAttackRequest(BaseModel):
#     n: int
#     e: int

class ECCPointsRequest(BaseModel):
    p: int = 17
    a: int = 2
    b: int = 2

class ECCExchangeRequest(BaseModel):
    p: int = 17
    a: int = 2
    b: int = 2
    gx: int = 5
    gy: int = 1
    n: int = 19


# =============================================================================
# SUBSTITUTION CIPHER ROUTES
# =============================================================================

@app.post("/api/substitution/encrypt")
def substitution_encrypt(req: SubEncryptRequest):
    key = req.key or sub.generate_random_key()
    if len(key) != 26 or len(set(key.upper())) != 26 or not key.isalpha():
        raise HTTPException(400, "Key must be 26 unique letters.")
    key = key.upper()
    ciphertext = sub.encrypt(req.plaintext, key)
    return {"plaintext": req.plaintext.upper(), "ciphertext": ciphertext, "key": key}


@app.post("/api/substitution/decrypt")
def substitution_decrypt(req: SubDecryptRequest):
    key = req.key.upper()
    if len(key) != 26 or len(set(key)) != 26:
        raise HTTPException(400, "Key must be 26 unique letters.")
    plaintext = sub.decrypt(req.ciphertext, key)
    return {"ciphertext": req.ciphertext.upper(), "plaintext": plaintext, "key": key}


@app.post("/api/substitution/analyze")
def substitution_analyze(req: SubAnalyzeRequest):
    result = sub.frequency_analysis(req.ciphertext)
    return result


# =============================================================================
# DOUBLE TRANSPOSITION ROUTES
# =============================================================================

@app.post("/api/transposition/encrypt")
def transposition_encrypt(req: TranspositionRequest):
    key1 = dt.parse_key(req.key1)
    key2 = dt.parse_key(req.key2)
    if key1 is None or key2 is None:
        raise HTTPException(400, "Keys must be space-separated integers, e.g. '3 1 4 2'.")
    after_first, ciphertext = dt.encrypt(req.text, key1, key2)
    return {
        "plaintext": req.text.upper().replace(' ', ''),
        "after_first_transpose": after_first,
        "ciphertext": ciphertext,
        "key1": key1,
        "key2": key2,
    }


@app.post("/api/transposition/decrypt")
def transposition_decrypt(req: TranspositionDecryptRequest):
    key1 = dt.parse_key(req.key1)
    key2 = dt.parse_key(req.key2)
    if key1 is None or key2 is None:
        raise HTTPException(400, "Keys must be space-separated integers.")
    plaintext = dt.decrypt(req.ciphertext.upper(), key1, key2)
    return {"ciphertext": req.ciphertext.upper(), "plaintext": plaintext}


# =============================================================================
# DES ROUTES
# =============================================================================

@app.post("/api/des/encrypt")
def des_encrypt(req: DESRequest):
    if req.key_hex:
        try:
            key = bytes.fromhex(req.key_hex)
            if len(key) != 8:
                raise HTTPException(400, "DES key must be exactly 8 bytes (16 hex chars).")
        except ValueError:
            raise HTTPException(400, "Invalid hex string for key.")
    else:
        key = des.generate_key()

    result = des.encrypt(req.plaintext, key)
    result['key_hex'] = key.hex().upper()
    # Round keys are bit lists — convert to hex for JSON transport
    result['round_keys_hex'] = [
        __import__('utils.bit_helpers', fromlist=['bits_to_bytes']).bits_to_bytes(rk).hex().upper()
        for rk in result['round_keys']
    ]
    del result['round_keys']
    return result


@app.post("/api/des/decrypt")
def des_decrypt(req: DESDecryptRequest):
    try:
        key = bytes.fromhex(req.key_hex)
    except ValueError:
        raise HTTPException(400, "Invalid key hex string.")
    try:
        result = des.decrypt(req.ciphertext_hex, key)
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))


# =============================================================================
# AES ROUTES
# =============================================================================

@app.post("/api/aes/encrypt")
def aes_encrypt(req: AESRequest):
    if req.key_size not in (128, 192, 256):
        raise HTTPException(400, "key_size must be 128, 192, or 256.")
    if req.key_hex:
        try:
            key = bytes.fromhex(req.key_hex)
        except ValueError:
            raise HTTPException(400, "Invalid key hex string.")
    else:
        key = aes.generate_key(key_size=req.key_size)

    result = aes.encrypt(req.plaintext, key)
    result['key_hex'] = key.hex().upper()
    from ciphers.aes.cipher import _state_to_bytes
    result['round_keys_hex'] = [_state_to_bytes(rk).hex().upper() for rk in result['round_keys']]
    del result['round_keys']
    del result['ciphertext_bytes']
    return result


@app.post("/api/aes/decrypt")
def aes_decrypt(req: AESDecryptRequest):
    try:
        key = bytes.fromhex(req.key_hex)
    except ValueError:
        raise HTTPException(400, "Invalid key hex string.")
    try:
        result = aes.decrypt(req.ciphertext_hex, key)
        del result['round_keys']
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))


# =============================================================================
# RSA ROUTES
# =============================================================================

# @app.post("/api/rsa/generate")
# def rsa_generate(req: RSAGenerateRequest):
#     bits_per_prime = req.key_bits // 2
#     if bits_per_prime < 16:
#         raise HTTPException(400, "key_bits must be at least 32.")
#     keys = rsa.generate_keys(bits=bits_per_prime)
#     return {
#         "e": keys['e'], "d": keys['d'], "n": keys['n'],
#         "p": keys['p'], "q": keys['q'], "phi": keys['phi'],
#         "key_bits": keys['key_bits'],
#     }


# @app.post("/api/rsa/encrypt")
# def rsa_encrypt_route(req: RSAEncryptRequest):
#     try:
#         result = rsa.encrypt(req.plaintext, req.e, req.n)
#         return result
#     except ValueError as e:
#         raise HTTPException(400, str(e))


# @app.post("/api/rsa/decrypt")
# def rsa_decrypt_route(req: RSADecryptRequest):
#     try:
#         plaintext = rsa.decrypt(req.chunks, req.d, req.n)
#         return {"plaintext": plaintext}
#     except Exception as e:
#         raise HTTPException(400, str(e))


# @app.post("/api/rsa/attack")
# def rsa_attack(req: RSAAttackRequest):
#     result = rsa.factorization_attack(req.n, req.e)
#     return result

@app.post("/api/rsa/generate")
def rsa_generate(req: RSAGenerateRequest):
    bits_per_prime = req.key_bits // 2
    if bits_per_prime < 16:
        raise HTTPException(400, "key_bits must be at least 32.")

    # Normalise optional string fields — treat empty string same as None
    custom_e = req.custom_e.strip() if req.custom_e and req.custom_e.strip() else None
    custom_p = req.custom_p.strip() if req.custom_p and req.custom_p.strip() else None
    custom_q = req.custom_q.strip() if req.custom_q and req.custom_q.strip() else None

    try:
        # ── Case A: user provided both p and q ────────────────────────────────
        if custom_p and custom_q:
            p = int(custom_p)
            q = int(custom_q)
            if p < 3 or not rsa._miller_rabin(p):
                raise HTTPException(400, f"{p} is not prime. Enter a valid prime number for p.")
            if q < 3 or not rsa._miller_rabin(q):
                raise HTTPException(400, f"{q} is not prime. Enter a valid prime number for q.")
            if p == q:
                raise HTTPException(400, "p and q must be different primes.")
            n   = p * q
            phi = (p - 1) * (q - 1)
            e   = int(custom_e) if custom_e else 65537
            if e < 3:
                raise HTTPException(400, f"e must be at least 3. Got {e}.")
            if math.gcd(e, phi) != 1:
                raise HTTPException(400,
                    f"e = {e} is not valid: gcd(e, phi(n)) must equal 1. "
                    f"Try e = 65537, or choose different primes.")
            d   = mod_inverse(e, phi)
            result = {'e': e, 'd': d, 'n': n, 'p': p, 'q': q, 'phi': phi}

        # ── Case B: user provided only e — generate p and q automatically ─────
        elif custom_e:
            e = int(custom_e)
            if e < 3 or e % 2 == 0:
                raise HTTPException(400,
                    f"e must be an odd integer >= 3 (common values: 3, 17, 65537). Got {e}.")
            # Try up to 10 key pairs until gcd(e, phi) = 1
            for _ in range(10):
                keys = rsa.generate_keys(bits=bits_per_prime)
                p, q = keys['p'], keys['q']
                phi  = (p - 1) * (q - 1)
                if math.gcd(e, phi) == 1:
                    d = mod_inverse(e, phi)
                    result = {'e': e, 'd': d, 'n': p * q, 'p': p, 'q': q, 'phi': phi}
                    break
            else:
                raise HTTPException(400,
                    f"e = {e} is not coprime with the generated phi after 10 attempts. "
                    f"Try e = 65537 or a different value.")

        # ── Case C: default — generate everything automatically ───────────────
        else:
            result = rsa.generate_keys(bits=bits_per_prime)

        return {
            "e":       str(result["e"]),
            "d":       str(result["d"]),
            "n":       str(result["n"]),
            "p":       str(result["p"]),
            "q":       str(result["q"]),
            "phi":     str(result["phi"]),
            "key_bits": result.get("key_bits", result["n"].bit_length()),
        }

    except HTTPException:
        raise
    except ValueError as err:
        raise HTTPException(400, str(err))


@app.post("/api/rsa/encrypt")
def rsa_encrypt_route(req: RSAEncryptRequest):
    try:
        e = int(req.e)
        n = int(req.n)

        result = rsa.encrypt(req.plaintext, e, n)

        return {
            "chunks":          [str(chunk) for chunk in result["chunks"]],
            "chunk_size_bytes": result["chunk_size_bytes"],
            "num_chunks":       result["num_chunks"],
        }

    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/rsa/decrypt")
def rsa_decrypt_route(req: RSADecryptRequest):
    try:
        d = int(req.d)
        n = int(req.n)

        chunks = [int(chunk) for chunk in req.chunks]

        plaintext = rsa.decrypt(chunks, d, n)

        return {
            "plaintext": plaintext
        }

    except Exception as e:
        raise HTTPException(400, str(e))


@app.post("/api/rsa/attack")
def rsa_attack(req: RSAAttackRequest):
    try:
        n = int(req.n)
        e = int(req.e)

        result = rsa.factorization_attack(n, e)

        safe_result = {}

        for key, value in result.items():
            if isinstance(value, int):
                safe_result[key] = str(value)
            elif isinstance(value, list):
                safe_result[key] = [
                    str(item) if isinstance(item, int) else item
                    for item in value
                ]
            else:
                safe_result[key] = value

        return safe_result

    except Exception as e:
        raise HTTPException(400, str(e))

# =============================================================================
# ECC ROUTES
# =============================================================================

@app.post("/api/ecc/points")
def ecc_points(req: ECCPointsRequest):
    try:
        points = ecc.get_all_curve_points(req.a, req.b, req.p)
        return {"points": points, "count": len(points)}
    except Exception as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/ecc/exchange")
def ecc_exchange(req: ECCExchangeRequest):
    try:
        G = (req.gx, req.gy)
        result = ecc.ecdh_key_exchange(G, req.a, req.p, req.n)
        return result
    except Exception as exc:
        raise HTTPException(400, str(exc))


# =============================================================================
# ANALYSIS SUITE ROUTES
# =============================================================================

class TimingRequest(BaseModel):
    plaintext: str

class BruteForceRequest(BaseModel):
    ciphertext: str
    timeout_seconds: int = 60
    max_attempts: int = 616


@app.post("/api/analysis/timing")
def analysis_timing(req: TimingRequest):
    # Input:  {"plaintext": "HELLO"}
    # Output: {"results": [{name, enc_ms, dec_ms, roundtrip_ok, note, error}, ...]}
    if not req.plaintext:
        raise HTTPException(400, "plaintext must not be empty.")
    results = run_timing_analysis(req.plaintext)
    return {"results": results}


@app.post("/api/analysis/brute_force")
def analysis_brute_force(req: BruteForceRequest):
    # Input:  {"ciphertext": "ITSSG", "timeout_seconds": 60}
    # Output: {"results": [{algorithm, attempted, elapsed_ms, found, guess, keys_tried, total_key_space, note}, ...]}
    if not req.ciphertext:
        raise HTTPException(400, "ciphertext must not be empty.")
    timeout      = max(1, min(req.timeout_seconds, 300))     # clamp 1–300 s
    max_attempts = max(1, min(req.max_attempts, 1_000_000))  # clamp 1–1 000 000
    results = run_brute_force(req.ciphertext, timeout_seconds=timeout, max_attempts=max_attempts)
    return {"results": results}


# =============================================================================
# PERFORMANCE ANALYSIS ROUTE
# =============================================================================

@app.get("/api/performance")
def performance(plaintext: Optional[str] = Query(default=None)):
    # Input:  optional ?plaintext=YOUR+TEXT query parameter
    # Output: timing results for all algorithms on that text (or the default if omitted)
    DEFAULT = "HELLO WORLD THIS IS A CRYPTOGRAPHY PERFORMANCE TEST MESSAGE"
    TEST = plaintext.strip() if plaintext and plaintext.strip() else DEFAULT
    RUNS = 5

    def avg_ms(fn, *args):
        start = time.perf_counter()
        for _ in range(RUNS):
            fn(*args)
        return round(((time.perf_counter() - start) / RUNS) * 1000, 4)

    # Keys generated outside the timing window
    sub_key    = sub.generate_random_key()
    des_key    = des.generate_key()
    aes128_key = aes.generate_key(128)
    aes192_key = aes.generate_key(192)
    aes256_key = aes.generate_key(256)
    rsa_keys   = rsa.generate_keys(bits=64)  # tiny — timing demo only
    G, a, p, n = (5, 1), 2, 17, 19

    results = [
        {
            "algorithm": "Substitution",
            "time_ms": avg_ms(sub.encrypt, TEST, sub_key),
            "key_info": "26-letter permutation key",
            "security": "Very Weak",
            "security_note": "Broken by frequency analysis",
            "key_bits": 88,
        },
        {
            "algorithm": "Double Transposition",
            "time_ms": avg_ms(dt.encrypt, TEST, [3,1,4,2], [2,4,1,3]),
            "key_info": "Two permutation keys",
            "security": "Weak",
            "security_note": "Letter frequencies unchanged",
            "key_bits": 64,
        },
        {
            "algorithm": "DES (Simplified)",
            "time_ms": avg_ms(des.encrypt, TEST, des_key),
            "key_info": "64-bit key, 8-round Feistel",
            "security": "Educational",
            "security_note": "Not production DES",
            "key_bits": 64,
        },
        {
            "algorithm": "AES-128",
            "time_ms": avg_ms(aes.encrypt, TEST, aes128_key),
            "key_info": "128-bit key, 10 rounds",
            "security": "Strong",
            "security_note": "NIST standard, unbroken",
            "key_bits": 128,
        },
        {
            "algorithm": "AES-192",
            "time_ms": avg_ms(aes.encrypt, TEST, aes192_key),
            "key_info": "192-bit key, 12 rounds",
            "security": "Very Strong",
            "security_note": "NIST standard, unbroken",
            "key_bits": 192,
        },
        {
            "algorithm": "AES-256",
            "time_ms": avg_ms(aes.encrypt, TEST, aes256_key),
            "key_info": "256-bit key, 14 rounds",
            "security": "Strongest",
            "security_note": "NIST standard, unbroken",
            "key_bits": 256,
        },
        {
            "algorithm": "RSA-128 (demo)",
            "time_ms": avg_ms(rsa.encrypt, "Hi", rsa_keys['e'], rsa_keys['n']),
            "key_info": "128-bit modulus (demo only)",
            "security": "Weak (demo)",
            "security_note": "Use 2048+ bits in production",
            "key_bits": 128,
        },
        {
            "algorithm": "ECC ECDH",
            "time_ms": avg_ms(ecc.ecdh_key_exchange, G, a, p, n),
            "key_info": "p=17 demo curve",
            "security": "Demo only",
            "security_note": "Real curves use 256+ bit p",
            "key_bits": 5,
        },
    ]

    return {"results": results, "test_string": TEST, "runs_per_algo": RUNS, "custom": bool(plaintext and plaintext.strip())}
