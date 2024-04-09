import unittest

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
        
        other.num = (-1)*other.num

        return self + other

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
        n = exp % (self.prime-1)
        num = pow(self.num, n, self.prime)

        return self.__class__(num, self.prime)


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
        return "Point({}, {}) on y2 = x3 + {}x + {}".format(self.x, self.y, self.a, self.b)
    
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



if __name__ == '__main__':
    unittest.main()
