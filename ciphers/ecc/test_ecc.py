# ciphers/ecc/test_ecc.py
#
# Unit Tests for ECC — Elliptic Curve Diffie-Hellman.
#
# Run from project root:
#   python -m unittest ciphers.ecc.test_ecc -v

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from ciphers.ecc import cipher as ecc_cipher


# Demo curve: y^2 = x^3 + 2x + 2 (mod 17)
P = 17   # prime modulus
A = 2    # curve coefficient a
B = 2    # curve coefficient b
G = (5, 1)  # generator point
N = 19   # order of G (G added to itself 19 times = point at infinity)


class TestPointAdd(unittest.TestCase):
    """Tests for the point_add() function."""

    def test_point_plus_infinity_equals_point(self):
        """P + O = P (adding the identity element returns P)."""
        result = ecc_cipher.point_add(G, None, A, P)
        self.assertEqual(result, G)

    def test_infinity_plus_point_equals_point(self):
        """O + P = P."""
        result = ecc_cipher.point_add(None, G, A, P)
        self.assertEqual(result, G)

    def test_point_plus_its_negative_is_infinity(self):
        """
        Adding a point to its negation (same x, negated y) gives the point at infinity.
        The negation of (x, y) on curve mod p is (x, p-y).
        """
        neg_G = (G[0], P - G[1])   # negation of G = (5, 17-1) = (5, 16)
        result = ecc_cipher.point_add(G, neg_G, A, P)
        self.assertIsNone(result)

    def test_known_point_addition(self):
        """
        Test against a known result on the demo curve.
        G = (5, 1). We know 2G = G + G is a specific point on this curve.
        """
        two_G = ecc_cipher.point_add(G, G, A, P)
        # 2G on y^2 = x^3 + 2x + 2 (mod 17) should be (6, 3)
        self.assertEqual(two_G, (6, 3))

    def test_result_is_on_the_curve(self):
        """Any result of point_add must satisfy the curve equation."""
        result = ecc_cipher.point_add(G, G, A, P)
        if result is not None:
            x, y = result
            lhs = (y * y) % P
            rhs = (pow(x, 3, P) + A * x + B) % P
            self.assertEqual(lhs, rhs, f"Point {result} is not on the curve!")


class TestScalarMultiply(unittest.TestCase):
    """Tests for the scalar_multiply() function."""

    def test_1_times_G_equals_G(self):
        """1 * G should equal G."""
        result = ecc_cipher.scalar_multiply(1, G, A, P)
        self.assertEqual(result, G)

    def test_2_times_G(self):
        """2 * G should equal G + G."""
        two_g_via_multiply = ecc_cipher.scalar_multiply(2, G, A, P)
        two_g_via_add      = ecc_cipher.point_add(G, G, A, P)
        self.assertEqual(two_g_via_multiply, two_g_via_add)

    def test_n_times_G_is_infinity(self):
        """n * G must be the point at infinity (definition of the order n)."""
        result = ecc_cipher.scalar_multiply(N, G, A, P)
        self.assertIsNone(result)

    def test_result_is_on_the_curve(self):
        """k * G must land on the curve for all valid k."""
        for k in range(1, N):  # test all valid private keys for this small curve
            result = ecc_cipher.scalar_multiply(k, G, A, P)
            if result is not None:
                x, y = result
                lhs = (y * y) % P
                rhs = (pow(x, 3, P) + A * x + B) % P
                self.assertEqual(lhs, rhs, f"k={k}: point {result} is not on the curve!")

    def test_commutativity(self):
        """
        Scalar multiplication must be commutative in the key exchange sense:
        a * (b * G) == b * (a * G)
        """
        a = 7
        b = 11
        a_times_bg = ecc_cipher.scalar_multiply(a, ecc_cipher.scalar_multiply(b, G, A, P), A, P)
        b_times_ag = ecc_cipher.scalar_multiply(b, ecc_cipher.scalar_multiply(a, G, A, P), A, P)
        self.assertEqual(a_times_bg, b_times_ag)


class TestGetAllCurvePoints(unittest.TestCase):
    """Tests for get_all_curve_points()."""

    def test_all_points_satisfy_curve_equation(self):
        """Every returned point must actually lie on the curve."""
        points = ecc_cipher.get_all_curve_points(A, B, P)
        for pt in points:
            x, y = pt
            lhs = (y * y) % P
            rhs = (pow(x, 3, P) + A * x + B) % P
            self.assertEqual(lhs, rhs, f"Point {pt} does not satisfy the curve equation!")

    def test_generator_G_is_in_point_list(self):
        """The generator point G must be one of the curve's points."""
        points = ecc_cipher.get_all_curve_points(A, B, P)
        self.assertIn(G, points)

    def test_known_number_of_points(self):
        """
        The demo curve y^2 = x^3 + 2x + 2 (mod 17) has exactly 18 affine points.
        Plus the point at infinity = 19 total, which is the group order N.
        """
        points = ecc_cipher.get_all_curve_points(A, B, P)
        self.assertEqual(len(points), 18)


class TestECDHKeyExchange(unittest.TestCase):
    """Tests for the full ECDH key exchange."""

    def test_shared_secrets_always_match(self):
        """
        The core ECDH property: Alice's shared secret must always equal Bob's.
        We run this 10 times with random keys to be confident.
        """
        for _ in range(10):
            result = ecc_cipher.ecdh_key_exchange(G, A, P, N)
            self.assertTrue(result['secrets_match'],
                "Alice and Bob got different shared secrets! ECDH is broken.")

    def test_result_contains_all_fields(self):
        """The result dict must have all required fields."""
        result = ecc_cipher.ecdh_key_exchange(G, A, P, N)
        required_fields = [
            'alice_private', 'alice_public',
            'bob_private', 'bob_public',
            'alice_shared', 'bob_shared', 'secrets_match'
        ]
        for field in required_fields:
            with self.subTest(field=field):
                self.assertIn(field, result)

    def test_public_keys_are_on_the_curve(self):
        """Alice's and Bob's public keys must be valid curve points."""
        result = ecc_cipher.ecdh_key_exchange(G, A, P, N)
        for label, pt in [('Alice public', result['alice_public']),
                           ('Bob public', result['bob_public'])]:
            if pt is not None:
                x, y = pt
                lhs = (y * y) % P
                rhs = (pow(x, 3, P) + A * x + B) % P
                self.assertEqual(lhs, rhs, f"{label} {pt} is not on the curve!")

    def test_private_keys_are_in_valid_range(self):
        """Private keys must be integers in range [2, n-1]."""
        result = ecc_cipher.ecdh_key_exchange(G, A, P, N)
        self.assertGreaterEqual(result['alice_private'], 2)
        self.assertLess(result['alice_private'], N)
        self.assertGreaterEqual(result['bob_private'], 2)
        self.assertLess(result['bob_private'], N)


if __name__ == '__main__':
    unittest.main(verbosity=2)
