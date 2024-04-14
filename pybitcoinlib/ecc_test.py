from unittest import TestCase

from ecc import *

class FieldElementTest(TestCase): 
    def test_ne(self):
        a = FieldElement(61, 137)
        b = FieldElement(61, 137)
        c = FieldElement(37, 137)
        self.assertEqual(a, b)
        self.assertTrue(a != c)
        self.assertFalse(a != b)

    def test_add(self):
        a = FieldElement(42, 137)
        b = FieldElement(135, 137)
        self.assertEqual(a + b, FieldElement(40, 137))

    def test_sub(self):
        a = FieldElement(1, 137)
        b = FieldElement(42, 137)
        self.assertEqual(a - b, FieldElement(96, 137))

    def test_mul(self):
        a = FieldElement(2, 7)
        b = FieldElement(5, 7)
        self.assertEqual(a * b, FieldElement(3, 7))

    def test_truediv(self):
        a = FieldElement(2, 19)
        b = FieldElement(7, 19)
        self.assertEqual(a / b, FieldElement(3, 19))


class PointTest(TestCase):
    def test_init(self):
        with self.assertRaises(ValueError):
            Point(0, 0, 5, 7)

        Point(3, 7, 5, 7)
        Point(18, 77, 5, 7)
        Point(2, -5, 5, 7)

    def test_ne(self):
        a = Point(3, 7, 5, 7)
        b = Point(3, 7, 5, 7)
        c = Point(3, -7, 5, 7)
        self.assertFalse(a != b)
        self.assertTrue(a != c)
        self.assertTrue(a != c)

    def test_add_identity(self):
        a = Point(3, 7, 5, 7)
        b = Point(None, None, 5, 7)
        self.assertEqual(a + b, a)
        self.assertEqual(b + b, b)

    def test_add_mirrored(self):
        a = Point(3, 7, 5, 7)
        b = Point(3, -7, 5, 7)
        inf = Point(None, None, 5, 7)
        self.assertEqual(a + b, inf)

    def test_add(self):
        a = Point(-1, -1, 5, 7)
        b = Point(3, 7, 5, 7)
        self.assertEqual(a + b, Point(2, -5, 5, 7))

    def test_add_equal(self):
        a = Point(-1, 1, 5, 7)
        self.assertEqual(a + a, Point(18, -77, 5, 7))


class ECCTest(TestCase):
    def test_on_curve(self):
        prime = 223

        a = FieldElement(0, prime)
        b = FieldElement(7, prime)

        valid_points = ((192, 105), (17, 56), (1, 193))
        invalid_points = ((200, 119), (42, 99))

        for x_raw, y_raw in valid_points:
            x = FieldElement(x_raw, prime)
            y = FieldElement(y_raw, prime)
            Point(x, y, a, b)

        for x_raw, y_raw in invalid_points:
            x = FieldElement(x_raw, prime)
            y = FieldElement(y_raw, prime)
            with self.assertRaises(ValueError):
                Point(x, y, a, b)

    def test_add(self):
        prime = 223
        a = FieldElement(0, prime)
        b = FieldElement(7, prime)

        values = [
            (170, 142, 60, 139, 220, 181),
            (47, 71, 17, 56, 215, 68),
            (143, 98, 76, 66, 47, 71)
        ]

        for x1, y1, x2, y2, x3, y3 in values:
            x1 = FieldElement(x1, prime)
            y1 = FieldElement(y1, prime)
            x2 = FieldElement(x2, prime)
            y2 = FieldElement(y2, prime)
            x3 = FieldElement(x3, prime)
            y3 = FieldElement(y3, prime)
            p1 = Point(x1, y1, a, b)
            p2 = Point(x2, y2, a, b)
            p3 = Point(x3, y3, a, b)
            self.assertEqual(p1 + p2, p3)

class S256Test(TestCase):

    def test_order(self):
        point = N * G
        self.assertIsNone(point.x)

    def test_pubpoint(self):
        # write a test that tests the public point for the following
        points = (
            # secret, x, y
            (7, 0x5cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc, 0x6aebca40ba255960a3178d6d861a54dba813d0b813fde7b5a5082628087264da),
            (1485, 0xc982196a7466fbbbb0e27a940b6af926c1a74d5ad07128c82824a11b5398afda, 0x7a91f9eae64438afb9ce6448a1c133db2d8fb9254e4546b6f001637d50901f55),
            (2**128, 0x8f68b9d2f63b5f339239c1ad981f162ee88c5678723ea3351b7b444c9ec4c0da, 0x662a9f2dba063986de1d90c2b6be215dbbea2cfe95510bfdf23cbf79501fff82),
            (2**240 + 2**31, 0x9577ff57c8234558f293df502ca4f09cbc65a6572c842b39b366f21717945116, 0x10b49c67fa9365ad7b90dab070be339a1daf9052373ec30ffae4f72d5e66d053),
        )

        # iterate over points
        for secret, x, y in points:
            # initialize the secp256k1 point (S256Point)
            point = S256Point(x, y)
            # check that the secret*G is the same as the point
            self.assertEqual(secret * G, point)

    def test_verify(self):
        point = S256Point(
            0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c,
            0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34)
        z = 0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60
        r = 0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395
        s = 0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4
        self.assertTrue(point.verify(z, Signature(r, s)))
        z = 0x7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d
        r = 0xeff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c
        s = 0xc7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6
        self.assertTrue(point.verify(z, Signature(r, s)))


class PrivateKeyTest(TestCase):
    def test_sign(self):
        pk = PrivateKey(randint(0, N))
        z = randint(0, 2**256)
        sig = pk.sign(z)
        self.assertTrue(pk.point.verify(z, sig))

        
if __name__ == '__main__':
    TestCase.main()