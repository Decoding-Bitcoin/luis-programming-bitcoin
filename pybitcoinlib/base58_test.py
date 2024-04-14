from unittest import TestCase
from hash import hash256

from base58 import *

class Base58Test(TestCase):
    def test_encode_base58(self):
        pre = bytes("McVnBUqpqxGe6N0zzw5W2GWByQuTOT8B", 'utf-8')
        post = "6D6FML3wytWNSsj4SYZE2HLQgSiAqTKkz6Xe1LM9Vmz9"
        self.assertEqual(post, encode_base58(pre))

    def test_encode_base58_check(self):
        pass
        