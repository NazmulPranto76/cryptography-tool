import random
from utils.bit_helpers import mod_pow


def _mod_inverse_prime(a, p):
    # Input:  3, 17
    # Output: 6   →   (3 * 6) % 17 == 1
    return mod_pow(a, p - 2, p)


def point_add(P, Q, a, p):
    # Input:  (5, 1), (5, 1), 2, 17 
    # Output: (6, 3)
    if P is None:
        return Q
    if Q is None:
        return P

    x1, y1 = P
    x2, y2 = Q

    # If the points are mirror images across the x-axis, cancel out
    if x1 == x2 and (y1 + y2) % p == 0:
        return None

    if P == Q:
        if y1 == 0:
            return None 
        numerator   = (3 * x1 * x1 + a) % p
        denominator = _mod_inverse_prime(2 * y1, p)
        slope = (numerator * denominator) % p
    else:
        # Two different points: draw a line through both and find where it hits the curve
        numerator   = (y2 - y1) % p
        denominator = _mod_inverse_prime((x2 - x1) % p, p)
        slope = (numerator * denominator) % p

    x3 = (slope * slope - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p

    return (x3, y3)


def scalar_multiply(k, P, a, p):
    # Input:  3, (5, 1), 2, 17
    # Output: (10, 6)   →   (5,1) added to itself 3 times on the demo curve
    result = None  
    addend = P

    while k > 0:
        if k & 1:
            result = point_add(result, addend, a, p)
        addend = point_add(addend, addend, a, p)
        k >>= 1

    return result


def get_all_curve_points(a, b, p):
    # Input:  2, 2, 17
    # Output: [(5,1), (6,3), (10,6), (3,1), (9,16), ...]
    points = []
    for x in range(p):
        rhs = (pow(x, 3, p) + a * x + b) % p
        for y in range(p):
            if (y * y) % p == rhs:
                points.append((x, y))
    return points


def ecdh_key_exchange(G, a, p, n):
    # Input:  (5, 1), 2, 17, 19
    # Output: {'alice_private': 7, 'alice_public': (0, 11), 'bob_private': 11,
    #          'bob_public': (14, 6), 'alice_shared': (13, 10), 'bob_shared': (13, 10),
    #          'secrets_match': True}
    alice_private = random.randint(2, n - 1)
    alice_public  = scalar_multiply(alice_private, G, a, p)

    bob_private   = random.randint(2, n - 1)
    bob_public    = scalar_multiply(bob_private, G, a, p)

    alice_shared  = scalar_multiply(alice_private, bob_public, a, p)
    bob_shared    = scalar_multiply(bob_private, alice_public, a, p)

    return {
        'alice_private': alice_private,
        'alice_public':  alice_public,
        'bob_private':   bob_private,
        'bob_public':    bob_public,
        'alice_shared':  alice_shared,
        'bob_shared':    bob_shared,
        'secrets_match': alice_shared == bob_shared,
    }
