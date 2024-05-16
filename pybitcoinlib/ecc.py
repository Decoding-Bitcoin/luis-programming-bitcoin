from hashlib import sha256
import hmac
from random import randint
from io import BytesIO

from base58 import *
from hash import *
from util import *


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
            prefix = b"\06f"
        if not testnet:
            prefix = b"\x00"
        
        return encode_base58_checksum(prefix + h160)
    

G = S256Point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
              0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)




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

    @classmethod
    def parse(cls, signature_bin):
        s = BytesIO(signature_bin)
        compound = s.read(1)[0]
        if compound != 0x30:
            raise SyntaxError("Bad Signature")
        length = s.read(1)[0]
        if length + 2 != len(signature_bin):
            raise SyntaxError("Bad Signature Length")
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        rlength = s.read(1)[0]
        r = int.from_bytes(s.read(rlength), 'big')
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        slength = s.read(1)[0]
        s = int.from_bytes(s.read(slength), 'big')
        if len(signature_bin) != 6 + rlength + slength:
            raise SyntaxError("Signature too long")
        return cls(r, s)

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



