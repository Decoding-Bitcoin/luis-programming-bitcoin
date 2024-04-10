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

if __name__ == '__main__':
    unittest.main()
