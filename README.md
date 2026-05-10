# Cryptography Tool — Complete Tutorial

<!-- markdownlint-disable MD024 MD036 -->

---

## Table of Contents

1. [What This Project Is](#1-what-this-project-is)
2. [Prerequisites and Setup](#2-prerequisites-and-setup)
3. [Running the CLI App](#3-running-the-cli-app)
4. [Running the Web App](#4-running-the-web-app)
5. [Algorithm Walkthroughs](#5-algorithm-walkthroughs)
   - [5.1 Substitution Cipher](#51-substitution-cipher)
   - [5.2 Double Transposition Cipher](#52-double-transposition-cipher)
   - [5.3 Simplified DES](#53-simplified-des)
   - [5.4 AES (128 / 192 / 256-bit)](#54-aes-128--192--256-bit)
   - [5.5 RSA](#55-rsa)
   - [5.6 ECC — Elliptic Curve Diffie-Hellman](#56-ecc--elliptic-curve-diffie-hellman)
   - [5.7 Performance and Security Analysis](#57-performance-and-security-analysis)
6. [Running the Tests](#6-running-the-tests)
7. [Project Structure Explained](#7-project-structure-explained)
8. [How the Code Is Organized](#8-how-the-code-is-organized)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. What This Project Is

This tool implements **6 cryptographic algorithms from scratch** in Python — meaning no external
cryptography libraries are used. Everything (S-boxes, Galois Field math, primality testing,
elliptic curve point arithmetic) is written by hand and fully commented for learning.

The project has **two interfaces**:

| Interface | How to launch | Best for |
| --------- | ------------- | -------- |
| **CLI** (command-line) | `python main.py` | Quick testing, step-by-step output |
| **Web App** | `uvicorn app:app` in `web/` | Visual exploration, comparison charts |

Both interfaces share the same core cipher logic — the same Python functions power both.

---

## 2. Prerequisites and Setup

### Prefer Docker?

If you have Docker Desktop installed you can skip all setup and run the web app in one command:

```bash
docker build -t cryptography-tool .
docker run -p 8000:8000 cryptography-tool
```

Then open [localhost:8000](http://localhost:8000) in your browser. See [DOCKER.md](DOCKER.md) for the full guide including DockerHub publishing.

### What you need (without Docker)

- **Python 3.10 or newer** — check with `python --version`
- An internet connection the first time you run the web app (loads Tailwind/Chart.js from CDN)

### Install web dependencies (one-time only)

```bash
pip install -r requirements.txt
```

This installs `fastapi` and `uvicorn`. The CLI needs no extra packages — only Python's standard library.

### Verify everything is working

```bash
cd "Project Folder Name"
python -m unittest discover -v
```

You should see **99 tests — all passing**. If any test fails, see [Troubleshooting](#9-troubleshooting).

---

## 3. Running the CLI App

From the project root folder:

```bash
python main.py
```

You will see:

```text
==================================================
    === Cryptography Tool ===
==================================================
  Classical Ciphers:
    1. Substitution Cipher        (encrypt, decrypt, freq analysis, brute force)
    2. Double Transposition       (encrypt, decrypt, freq analysis)

  Symmetric (Secret Key) Ciphers:
    3. DES  — Simplified 8-Round Feistel  (encrypt, decrypt, round keys)
    4. AES  — AES-128 from scratch        (encrypt, decrypt, round keys)

  Public Key (Asymmetric) Ciphers:
    5. RSA  — Key gen, encrypt, decrypt, factorization attack
    6. ECC  — Domain params, all points, ECDH key exchange

  Analysis:
    7. Performance & Security Comparison (all algorithms)

    0. Exit
==================================================
  Select [0-7]:
```

Type a number and press **Enter** to enter that section.

---

## 4. Running the Web App

### Homepage

When you first open the web app you will see an **animated homepage**:

- A **matrix rain** background of falling characters
- A terminal box that **types "WELCOME TO CRYPTOGRAPHY PROJECT"** character by character,
  then deletes it, then re-types the same text **encrypted** using the selected algorithm
- **7 floating algorithm bubbles** — click any bubble to switch which algorithm is used
  for the live encryption animation
- **"Enter the Tool"** button to go to the main cipher app

The encrypted values are pre-computed and hard-coded so the animation is always instant.

### Starting the server

Open a terminal, navigate to the `web/` folder, and run:

```bash
cd "Project_Folder/web"
python -m uvicorn app:app --host 0.0.0.0 --port 8000
```

You will see:

```text
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
```

**Keep this terminal open.** The server stops when you close it.

### Opening in the browser

Go to <http://localhost:8000> in any browser (Chrome, Firefox, Edge).

### Using the app

- The **left sidebar** lists all 6 algorithms plus the Performance page.
- Click any algorithm to open it.
- Each algorithm has **tabs** (e.g. Encrypt / Decrypt / Round Keys).
- Fill in the input fields and click the button — results appear instantly below.
- The **Performance** page runs a live benchmark and shows a bar chart.

### Stopping the server

Press **Ctrl + C** in the terminal where uvicorn is running.

---

## 5. Algorithm Walkthroughs

---

### 5.1 Substitution Cipher

#### What it does

Replaces each letter in the plaintext with a different letter according to a fixed mapping called
the **key**. The key is a 26-letter permutation of the alphabet.

```text
Key:       QWERTYUIOPASDFGHJKLZXCVBNM
Mapping:   A→Q   B→W   C→E   D→R   E→T   ...   Z→M
```

Non-letter characters (spaces, numbers, punctuation) pass through unchanged.

#### Example key table

```text
Plain:  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
Cipher: Q W E R T Y U I O P A S D F G H J K L Z X C V B N M
```

#### CLI session example

```text
Select [0-7]: 1

  Enter 26-letter key (or press Enter for random): [press Enter]
  Random key generated: MXKQZABCDE...

  1. Encrypt
  Your choice: 1
  Enter plaintext to encrypt: HELLO WORLD

  Plaintext  : HELLO WORLD
  Key        : MXKQZABCDE...
  Ciphertext : AZIIB WBKIQ
  Roundtrip check (decrypt): HELLO WORLD
```

#### Frequency analysis (attack demo)

Choose option 3 (Frequency Analysis) and paste in a ciphertext. The tool counts how often each
letter appears and maps the most frequent cipher letter to 'E', the next to 'T', and so on.
This is why substitution ciphers are weak — letter frequencies of the original text are preserved,
leaking information about the key.

**Security assessment:** Very weak. Any ciphertext longer than ~20 characters can be broken
by frequency analysis without knowing the key. Do not use for any real-world purpose.

---

### 5.2 Double Transposition Cipher

#### What it does

Rearranges (transposes) letters rather than replacing them. Applied **twice** with two different
keys for stronger security than a single transposition.

Step 1 — First transposition with Key 1 = `3 1 4 2`:

```text
Write plaintext into a grid row by row:
    Col 0  Col 1  Col 2  Col 3
    H      E      L      L
    O      W      O      R
    L      D      X      X     ← 'X' pads the last row

Key [3,1,4,2]: sort columns by key value to get reading order.
  Priority 1 = Col 1,  Priority 2 = Col 3,  Priority 3 = Col 0,  Priority 4 = Col 2
```

Step 2 — Second transposition (Key 2) applied to the result of Step 1.

#### CLI session example

```text
Select [0-7]: 2

  Enter Key 1 (e.g. '3 1 4 2'): 3 1 4 2
  Enter Key 2 (e.g. '2 4 1 3'): 2 4 1 3

  1. Encrypt
  Your choice: 1
  Enter plaintext to encrypt: HELLO WORLD

  Plaintext          : HELLOWORLD
  After 1st transpose: WDXELRHOLOX
  Final ciphertext   : RXELWDHOOLX
  Roundtrip check    : HELLOWORLD
```

> **Note:** Spaces are stripped before transposition. Padding 'X' characters may appear at the
> end of decrypted text for messages that do not fill the grid exactly.

**Security assessment:** Weak. Transposition ciphers do not change letter frequencies — frequency
analysis still works. Combining with a substitution cipher creates a much stronger "product cipher",
the historical predecessor of modern block ciphers.

---

### 5.3 Simplified DES

#### What it does

DES (Data Encryption Standard) is a **symmetric block cipher** — the same key encrypts and decrypts.
This is a **simplified educational version**:

- Block size: **64 bits (8 bytes)**
- Key size: **64 bits (8 bytes)**, auto-generated
- Rounds: **8** (production DES uses 16)
- Mode: **ECB** — each 8-byte block encrypted independently

Any-length input is supported — the plaintext is split into 8-byte blocks, each encrypted
separately, with PKCS-style padding on the last block.

#### How the Feistel structure works

```text
Each round:
  Block split → Left (L) | Right (R)  (32 bits each)

  new_R = L XOR F(R, round_key)
  new_L = R

  ↓ Repeat for 8 rounds ↓

Final ciphertext = L | R
```

Decryption applies the same process in **reverse round order**.

#### CLI session example

```text
Select [0-7]: 3

  Auto-generated key (hex): A3F72B019C45ED80

  1. Encrypt  (any length plaintext)
  Your choice: 1
  Enter plaintext (any length): Attack at dawn!

  Plaintext   : Attack at dawn!
  Blocks used : 2
  Ciphertext  : 3A9CF102B8E740D17F2C01A4593DE028
  Roundtrip   : Attack at dawn!

  3. Show All Round Keys
  Your choice: 3

  All 8 Round Keys (hex):
    Round 1: 47B9C023F1A05E8D
    Round 2: 8F3C12A045E7BD90
    ...
```

**Security assessment:** Educational only. Real DES has a 56-bit effective key and was officially
retired in 2001 after being broken. Use AES for any real application.

---

### 5.4 AES (128 / 192 / 256-bit)

#### What it does

AES (Advanced Encryption Standard) is the **current gold standard** for symmetric encryption.
This is a **full from-scratch implementation** including all four core operations:

| Operation | What it does |
| --------- | ------------ |
| **SubBytes** | Each byte is replaced using a 256-entry S-Box lookup table |
| **ShiftRows** | Each row of the 4×4 state matrix is rotated left |
| **MixColumns** | Each column is multiplied by a fixed matrix in GF(2⁸) |
| **AddRoundKey** | Every byte is XORed with the current round key |

Three key sizes are supported:

| Variant | Key length | Rounds | Round keys generated |
| ------- | ---------- | ------ | -------------------- |
| AES-128 | 16 bytes   | 10     | 11                   |
| AES-192 | 24 bytes   | 12     | 13                   |
| AES-256 | 32 bytes   | 14     | 15                   |

Any-length input is handled using PKCS#7 padding — the plaintext is padded to a multiple of
16 bytes, then each 16-byte block is encrypted independently.

#### CLI session example

```text
Select [0-7]: 4

  Select AES variant:
    1 = AES-128  (16-byte key, 10 rounds)
    2 = AES-192  (24-byte key, 12 rounds)
    3 = AES-256  (32-byte key, 14 rounds)
  Choice [1/2/3, default=1]: 3

  Variant : AES-256
  Key (hex): 3A1F9C04B72E5D8A... (32 bytes)
  Round keys generated: 15

  1. Encrypt  (any length plaintext)
  Your choice: 1
  Enter plaintext (any length): The quick brown fox jumps over the lazy dog

  Variant      : AES-256
  Plaintext    : The quick brown fox jumps over the lazy dog
  Blocks used  : 3
  Ciphertext   : 8F3A...(96 hex chars)
  Roundtrip    : The quick brown fox jumps over the lazy dog
```

**NIST validation:** The AES-128 implementation is validated against the official NIST FIPS 197
test vector (see `ciphers/aes/test_aes.py`). If that test passes, the S-Box, MixColumns, and
key expansion are all correct.

**Security assessment:** Strong. AES-128 is unbroken and is the standard for virtually all
encrypted communication today (TLS, disk encryption, VPNs). AES-256 provides extra margin
against future attacks, including quantum computers.

---

### 5.5 RSA

#### What it does

RSA is a **public-key (asymmetric) cipher** — there are two different keys:

- **Public key `(e, n)`** — shared openly, used to encrypt
- **Private key `(d, n)`** — kept secret, used to decrypt

#### Key generation steps

```text
1. Pick two large primes:  p, q           (using Miller-Rabin primality test)
2. Compute modulus:        n = p * q
3. Compute totient:        phi = (p-1)(q-1)
4. Choose public exponent: e = 65537
5. Compute private key:    d = modular_inverse(e, phi)

Public key:   (e, n)
Private key:  (d, n)
```

#### Encryption and Decryption

```text
Encrypt:  c = m^e mod n
Decrypt:  m = c^d mod n
```

Any-length messages are supported via automatic **chunking** — the message bytes are split into
blocks smaller than `n`, each block is encrypted separately, and chunks are reassembled on
decryption.

#### CLI session example

```text
Select [0-7]: 5

  1. Generate Key Pair
  Your choice: 1
  Key size [1=512-bit, 2=1024-bit]: 1

  Generating 512-bit RSA key pair...
  p   = 76847239142...
  n   = 70023487561...
  Public  key: e = 65537
  Private key: d = 34891029...

  2. Encrypt  (any length message)
  Your choice: 2
  Enter message (any length): Hello RSA!

  Chunk size    : 63 bytes
  Total chunks  : 1
  Chunk 1 (int) : 78234059182736...

  3. Decrypt
  Your choice: 3
  Decrypted: Hello RSA!
```

#### Factorization attack demo (option 4)

The attack demo generates a tiny RSA key (16-bit primes → 32-bit modulus) and uses
**Pollard's Rho algorithm** to factor `n` and recover the private key `d` from only the
public key `(e, n)`.

```text
  4. Factorization Attack Demo

  n (public) = 2847361917,  e = 65537
  Running Pollard's Rho factorization...

  SUCCESS after 3 attempt(s)!
  Found p = 49871,  q = 57107
  Recovered d = 1928374650...
  Verified d == real d? True
```

> This works because 32-bit numbers are tiny. Real 512-bit+ keys take billions of years to
> factor on any classical computer.

**Security assessment:** Key-size dependent. 512-bit keys can be factored by modern hardware.
Use 2048-bit or 4096-bit keys in real applications. RSA is used for key exchange and digital
signatures — not bulk data encryption.

---

### 5.6 ECC — Elliptic Curve Diffie-Hellman

#### What it does

ECC performs a **key exchange** — Alice and Bob agree on a shared secret over an insecure
channel, without ever transmitting the secret itself.

The math operates on **points on an elliptic curve** defined by:

```text
y^2 ≡ x^3 + ax + b  (mod p)
```

The default demo curve is `y^2 = x^3 + 2x + 2 (mod 17)`, generator point `G = (5, 1)`,
order `n = 19`.

#### ECDH key exchange steps

```text
Both agree on: curve parameters (p, a, b), generator G, order n

Alice picks private key a  (random integer 2 to n-1)
Alice computes public key A = a * G

Bob picks private key b    (random integer 2 to n-1)
Bob computes public key B = b * G

Alice computes shared = a * B  =  a * b * G
Bob   computes shared = b * A  =  b * a * G
                                 ↑ same point — shared secret!
```

An eavesdropper sees `G`, `A`, and `B` — computing `a` from `A = a * G` is the
**Elliptic Curve Discrete Logarithm Problem**, which is infeasible for large curves.

#### CLI session example

```text
Select [0-7]: 6

  Use custom curve parameters? (y/N): N

  Curve: y^2 = x^3 + 2x + 2 (mod 17)
  Generator G = (5, 1),  Order n = 19

  1. Show All Points on the Curve
  Your choice: 1

  Found 18 affine points (+ 1 point at infinity):
    (5, 1)  (6, 3)  (10, 6)  (3, 1)  (9, 16)  ...

  2. ECDH Key Exchange
  Your choice: 2

  Alice's private key (a)   : 7
  Alice's public key  (A=aG): (0, 11)

  Bob's   private key (b)   : 11
  Bob's   public key  (B=bG): (14, 6)

  Alice computes: a * B = (13, 10)
  Bob   computes: b * A = (13, 10)

  Shared secrets match: True
  Shared Secret: (13, 10)
```

**Security assessment:** The demo curve (p=17) is not secure — it has only 18 points and can
be bruted in milliseconds. Real ECC uses curves like NIST P-256 where `p ≈ 2^256`. A 256-bit
ECC key offers roughly the same security as a 3072-bit RSA key, with much smaller key sizes.

---

### 5.7 Performance and Security Analysis

#### CLI — option 7

Times all algorithms on a common test string (averaged over 5 runs) and prints a table:

```text
  Algorithm              Avg Time       Key / Security Info          Rating
  -----------------------------------------------------------------------
  Substitution           0.0046 ms      ~26 bits                     Very Weak
  Double Transposition   0.0103 ms      ~26 bits                     Weak
  DES (Simplified)       0.0339 ms      64-bit block / 64-bit key    Educational only
  AES-128                1.0258 ms      128-bit key, unbroken         Strong
  RSA-512                24.3 ms        512-bit modulus               Moderate
  ECC (p=17 demo)        0.0125 ms      Tiny demo curve               Demo only
```

Followed by a written security summary for each algorithm.

#### Web app — Performance page

Click **Performance** in the sidebar to see:

- An **interactive bar chart** (logarithmic scale, color-coded by security level)
- A **results table** with ratings and notes for every algorithm
- Two analysis cards: Security Ranking and Performance Insights

The benchmark runs live when you navigate to the page — results arrive in a few seconds.

---

## 6. Running the Tests

The test suite verifies every cipher function individually. Tests import only `cipher.py` —
never `menu.py` — so they work regardless of which interface you use.

```bash
# Run all 99 tests (from project root)
python -m unittest discover -v

# Run tests for one specific module
python -m unittest ciphers.aes.test_aes -v
python -m unittest ciphers.rsa.test_rsa -v
python -m unittest ciphers.ecc.test_ecc -v
python -m unittest ciphers.des.test_des -v
python -m unittest ciphers.substitution.test_substitution -v
python -m unittest ciphers.double_transposition.test_double_transposition -v
```

Expected output:

```text
test_aes192_roundtrip (ciphers.aes.test_aes.TestAESMultiKeySize) ... ok
test_aes256_roundtrip (ciphers.aes.test_aes.TestAESMultiKeySize) ... ok
test_nist_encrypt_vector (ciphers.aes.test_aes.TestAESKnownVector) ... ok
...
Ran 99 tests in 0.019s

OK
```

---

## 7. Project Structure Explained

```text
Project Folder/
│
├── main.py                 ← Start here for CLI: python main.py
├── requirements.txt        ← Web app dependencies (fastapi, uvicorn)
├── TUTORIAL.md             ← This file
│
├── utils/                  ← Shared math and display helpers
│   ├── bit_helpers.py      ← bytes_to_bits, mod_inverse, mod_pow, extended_gcd...
│   └── display_helpers.py  ← print_separator, print_freq_chart
│
├── ciphers/                ← One sub-package per algorithm
│   ├── substitution/
│   │   ├── cipher.py       ← Pure functions only (no print/input)
│   │   ├── menu.py         ← CLI menus (imports cipher.py)
│   │   └── test_*.py       ← Unit tests (imports cipher.py only)
│   ├── double_transposition/   ← Same structure
│   ├── des/                    ← Same structure
│   ├── aes/                    ← Same structure
│   ├── rsa/                    ← Same structure
│   └── ecc/                    ← Same structure
│
└── web/
    ├── app.py              ← FastAPI server (imports cipher.py directly)
    ├── requirements.txt    ← fastapi, uvicorn
    └── static/
        └── index.html      ← Single-page UI (Tailwind + Alpine.js + Chart.js)
```

---

## 8. How the Code Is Organized

Understanding the separation of concerns helps when reading or modifying the code.

#### The three-layer architecture

```text
┌─────────────────────────────────────┐
│  UI Layer (what the user sees)      │
│  CLI:  menu.py files                │
│  Web:  index.html + app.py routes   │
├─────────────────────────────────────┤
│  Logic Layer (the actual crypto)    │
│  cipher.py in each cipher folder    │
│  → pure functions, no I/O           │
│  → imported by BOTH CLI and web     │
├─────────────────────────────────────┤
│  Utility Layer (shared helpers)     │
│  utils/bit_helpers.py               │
│  utils/display_helpers.py           │
└─────────────────────────────────────┘
```

#### Why cipher.py has no print() or input()

The `cipher.py` files are pure functions: they take data in and return data out. No printing,
no user prompts. This design means:

- The CLI (`menu.py`) can call them interactively
- The web server (`app.py`) can call them from an HTTP route
- Tests can call them without mocking anything
- A future mobile app or Jupyter notebook can import them directly

#### Adding a new cipher

If you ever want to add a 7th algorithm, the pattern is:

1. Create `ciphers/newcipher/cipher.py` — pure logic, returns dicts
2. Create `ciphers/newcipher/menu.py` — calls cipher.py, handles user I/O
3. Create `ciphers/newcipher/test_newcipher.py` — unit tests
4. Add the import and menu option in `main.py`
5. Add API routes in `web/app.py`

---

## 9. Troubleshooting

### "ModuleNotFoundError: No module named 'fastapi'"

```bash
pip install fastapi uvicorn
```

### "python is not recognized" on Windows

Try:

```bash
py -3 main.py
py -3 -m uvicorn app:app
```

Or use the full path to your Python 3 executable.

### Tests fail after modifying cipher.py

Run the specific test file to see the exact error:

```bash
python -m unittest ciphers.aes.test_aes -v
```

Common causes:

- Changed the return type of a function (e.g., `encrypt()` now returns a dict instead of bytes)
- Renamed a function without updating the test
- Changed padding behavior

### Web app shows "Connection refused"

The server is not running. Start it:

```bash
cd web
python -m uvicorn app:app --host 0.0.0.0 --port 8000
```

Keep the terminal open — closing it stops the server.

### Web app API returns an error

Open your browser's developer tools (F12), go to the **Network** tab, and look at the failing
API request. The response body will contain an error message explaining what went wrong.

### AES decryption fails with "Invalid hex string"

Make sure you are using the **same key** that was used for encryption. The key is shown in the
encrypt output — copy it exactly and paste it into the decrypt key field.

### RSA decryption returns garbled text

RSA decryption only works with the **private key `d`** that pairs with the public key `e`
used to encrypt. If you generate a new key pair, old ciphertext cannot be decrypted with the
new key.

### DES or AES roundtrip gives wrong result

Run the unit tests:

```bash
python -m unittest ciphers.des.test_des -v
python -m unittest ciphers.aes.test_aes -v
```

All roundtrip tests should pass. If they do not, the issue is reproducible and can be debugged.

---

## Quick Reference Card

| Task | Command |
| ---- | ------- |
| Start CLI | `python main.py` |
| Start web server | `cd web && python -m uvicorn app:app --port 8000` |
| Open web UI | Browser → <http://localhost:8000> |
| Open API docs | Browser → <http://localhost:8000/docs> |
| Run all tests | `python -m unittest discover -v` |
| Run one module's tests | `python -m unittest ciphers.aes.test_aes -v` |
| Generate AES-256 key | CLI option 4, then select variant 3 |
| See all ECC curve points | CLI option 6, then option 1 |
| Run factorization attack | CLI option 5, then option 4 |
| See performance chart | Web — click Performance in the sidebar |
