from util import *
from network import GenericMessage

BIP37_CONSTANT = 0xfba4c795

class BloomFilter:
    def __init__(self, size, function_count, tweak):
        self.size = size
        self.bit_field = [0] * (size * 8)
        self.function_count = function_count
        self.tweak = tweak

    def add(self, item):
        # pass item through all hash functions and flip corresponding bits
        for i in range(self.function_count):
            seed = i * BIP37_CONSTANT + self.tweak

            h = murmur3(item, seed=seed)

            bit = h % (self.size * 8)

            self.bit_field[bit] = 1

    def filter_bytes(self):
        return bit_field_to_bytes(self.bit_field)
    
    def filterload(self, flag=1):
        payload = encode_varint(self.size)
        payload += self.filter_bytes()
        payload += int_to_little_endian(self.function_count, 4)
        payload += int_to_little_endian(self.tweak, 4)
        payload += int_to_little_endian(flag, 1)
        return GenericMessage(b"filterload", payload)