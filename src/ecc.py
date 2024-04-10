from hashlib import sha256
import hmac
from random import randint
import unittest

from utils import encode_base58_checksum, hash160


class FieldElement:
    def __init__(self, num, prime):
        if num >= prime or num < 0:
            error = "{} is outside of the field range [0, {}]".format(num, prime-1)
            raise ValueError(error)

        self.num = num
        self.prime = prime

    def __repr__(self):
        return "FieldElement_{}({})".format(self.prime, self.num)

    def __eq__(self, other):
        if other is None:
            return False
        else:
            return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        return not(self == other)

    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot add elements from different fields to each other.")
        
        num = (self.num + other.num) % self.prime

        return self.__class__(num, self.prime)

    def __sub__(self, other):
        num = (self.num - other.num) % self.prime

        return self.__class__(num, self.prime)

    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot multiply elements from different fields to each other.")
        
        num = (self.num * other.num) % self.prime

        return self.__class__(num, self.prime)

    # using fermat's little theorem
    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError("Cannot divide elements from different fields by each other.")
        
        num = (self.num * pow(other.num, self.prime-2, self.prime)) % self.prime

        return self.__class__(num, self.prime)

    def __pow__(self, exp):
        n = exp % (self.prime - 1)
        num = pow(self.num, n, self.prime)

        return self.__class__(num, self.prime)
    
    def __rmul__(self, coef):
        num = (self.num * coef) % self.prime
        return self.__class__(num=num, prime=self.prime)


class FieldElementTest(unittest.TestCase): 
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


class Point:
    def __init__(self, x, y, a, b):
        self.x = x 
        self.y = y
        self.a = a
        self.b = b

        if self.x is None and self.y is None:
            return

        if (self.y)**2 != (self.x)**3 + a*x + b:
            raise ValueError("The point ({}, {}) is not on the curve.".format(self.x, self.y))

    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        elif isinstance(self.x, FieldElement):
            return 'Point({},{})_{}_{} FieldElement({})'.format(
                self.x.num, self.y.num, self.a.num, self.b.num, self.x.prime)
        else:
            return 'Point({},{})_{}_{}'.format(self.x, self.y, self.a, self.b)


    def __eq__(self, other):
        return \
            self.x == other.x and self.y == other.y and \
            self.a == other.a and self.b == other.b

    def __ne__(self, other):
        return not(self == other)

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError('Points {}, {} are not on the same curve'.format(self, other))

        # the point at infinity is the identity on EC point addition
        if self.x is None:
            return other

        if other.x is None:
            return self

        # when P1 and P2 are mirrored about the x-axis
        if (self.x == other.x) and (self.y != other.y): 
            return self.__class__(None, None, self.a, self.b)

        # when points have different x values
        if (self.x != other.x):
            x1, y1 = self.x, self.y
            x2, y2 = other.x, other.y

            s = (y2 - y1) / (x2 - x1)

            x3 = s**2 - x1 - x2
            y3 = s * (x1 - x3) - y1

            return self.__class__(x3, y3, self.a, self.b)

        # when P1 = P2, the line will be tangent to the curve and intersect it twice
        if (self == other):
            x1, y1 = self.x, self.y

            s = (3 * x1**2 + self.a) / (2 * y1)

            x3 = s**2 - 2*x1
            y3 = s * (x1 - x3) - y1

            return self.__class__(x3, y3, self.a, self.b)

    def __rmul__(self, coef):
        curr = self
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            if coef & 0x01:
                result += curr
            curr += curr
            coef >>= 1
        return result

class PointTest(unittest.TestCase):
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


class ECCTest(unittest.TestCase):
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
        

P = 2**256 - 2**32 - 977
class S256Field(FieldElement):
    def __init__(self, num, prime=None):
        super().__init__(num=num, prime=P)

    def __repr__(self):
        return "{:x}".format(self.num).zfill(64)
    
    def sqrt(self):
        return self**((P + 1) // 4)
    
A = 0
B = 7
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
class S256Point(Point):
    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)

        if type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __repr__(self):
        if self.x is None:
            return 'S256Point(infinity)'
        else:
            return 'S256Point({}, {})'.format(self.x, self.y)

    def __rmul__(self, coef):
        coef = coef % N
        return super().__rmul__(coef)
    
    def verify(self, z, sig):
        s_inv = pow(sig.s, N-2, N)
        u = (z * s_inv) % N
        v = (sig.r * s_inv) % N
        total = u*G + v*self

        return total.x.num == sig.r
    
    def sec(self, compressed=True):
        '''get binary of the SEC format'''
        if compressed:
            if self.y.num % 2 == 0:
                return b"\x02" + self.x.num.to_bytes(32, "big")
            else:
                return b"\x03" + self.y.num.to_bytes(32, "big")
            
        if not compressed:
            return b"\x04" + self.x.num.to_bytes(32, "big") + self.y.num.to_bytes(32, "big")
        
    @classmethod
    def parse(self, sec_bin):
        '''returns a Point object from a SEC binary (not hex)'''
        if sec_bin[0] == 4:
            x = int.from_bytes(sec_bin[1:33], "big")
            y = int.from_bytes(sec_bin[33:65], "big")
            return S256Point(x, y)
        
        is_even = (sec_bin[0] == 2)

        x = S256Field(int.from_bytes(sec_bin[1:], "big"))

        alpha = x**3 + S256Field(B)
        beta = alpha.sqrt()

        if beta.num % 2 == 0:
            even_beta = beta
            odd_beta = S256Field(P - beta.num)
        if beta.num % 2 == 1:
            even_beta = S256Field(P - beta.num)
            odd_beta = beta

        if is_even:
            return S256Point(x, even_beta)
        if not is_even:
            return S256Point(x, odd_beta)
        
    def hash160(self, compressed=True):
        return hash160(self.sec(compressed))
    
    def address(self, compressed=True, testnet=False):
        h160 = self.hash160(compressed)

        if testnet:
            prefix = b"\6f"
        if not testnet:
            prefix = b"\x00"
        
        return encode_base58_checksum(prefix + h160)
    

G = S256Point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
              0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


class S256Test(unittest.TestCase):

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


class Signature:
    def __init__(self, r, s):
        self.r = r
        self.s = s

    def __repr__(self):
        return "Signature({:x},{:x})".format(self.r, self.s)
    
    def der(self):
        rbin = self.r.to_bytes(32, "big")
        rbin = rbin.lstrip(b"\x00")

        if rbin[0] & 0x80:
            rbin = b"\x00" + rbin
        # wrap r in a TLV
        result_r = bytes([2, len(rbin)]) + rbin

        sbin = self.s.to_bytes(32, "big")
        sbin = sbin.lstrip(b"\x00")

        if sbin[0] & 0x80:
            sbin = b"\x00" + sbin
        # wrap s in a TLV
        result_s = bytes([2, len(sbin)]) + sbin

        # wrap the r and s TLVs in another TLV
        return bytes([0x30, len(rbin)+len(sbin)]) + result_r + result_s


class PrivateKey:
    def __init__(self, secret):
        self.secret = secret    # private key
        self.point = secret * G # public key point

    def hex(self):
        return "{:x}".format(self.secret).zfill(64)
    
    def deterministic_k(self, z):
        k = b"\x00" * 32
        v = b"\x01" * 32

        if z >N:
            z = z - N
        
        z_bytes = z.to_bytes(32, "big")
        secret_bytes = self.secret.to_bytes(32, "big")
        
        k = hmac.new(k, v + b"\x00" + secret_bytes + z_bytes, sha256).digest()
        v = hmac.new(k, v, sha256).digest()
        k = hmac.new(k, v + b"\x01" + secret_bytes + z_bytes, sha256).digest()
        v = hmac.new(k, v, sha256).digest()

        while 1:
            v = hmac.new(k, v, sha256).digest()
            candidate = int.from_bytes(v, "big")
            if candidate >= 1 and candidate < N:
                return candidate
            k = hmac.new(k, v + b"\x00", sha256).digest()
            v = hmac.new(k, v, sha256).digest()

    # z = sha256(message)
    def sign(self, z):
        # k is the nonce
        k = self.deterministic_k(z)
        r = (k*G).x.num
        # multiplicative inverse
        k_inv = pow(k, N-2, N)
        s = ((z + r*self.secret) * k_inv) % N

        # get low-s values only to stop signature malleability
        # segwit fixes this: the signature is not used to compute the txid anymore
        if s > N/2:
            s = N - s

        return Signature(r, s)
    
    def wif(self, compressed=True, testnet=False):
        secret_bytes = self.secret.to_bytes(32, "big")

        if testnet:
            prefix = b"\xef"
        if not testnet:
            prefix = b"\x80"

        if compressed:
            suffix = b"\x01"
        if not compressed:
            suffix = b""

        return encode_base58_checksum(prefix + secret_bytes + suffix)


class PrivateKeyTest(unittest.TestCase):
    def test_sign(self):
        pk = PrivateKey(randint(0, N))
        z = randint(0, 2**256)
        sig = pk.sign(z)
        self.assertTrue(pk.point.verify(z, sig))


if __name__ == '__main__':
    unittest.main()
