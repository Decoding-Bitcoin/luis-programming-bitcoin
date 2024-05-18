from util import *

class Block:
    def __init__(self, version, prev_block, merkle_root, timestamp, bits, nonce, tx_hashes=None):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root = merkle_root
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.tx_hashes = tx_hashes

    # read a byte stream into a Block instance
    @classmethod
    def parse(cls, s):
        version = little_endian_to_int(s.read(4))
        prev_block = s.read(32)[::-1]
        merkle_root = s.read(32)[::-1]
        timestamp = little_endian_to_int(s.read(4))
        bits = s.read(4)
        nonce = s.read(4)
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += self.prev_block[::-1]
        result += self.merkle_root[::-1]
        result += int_to_little_endian(self.timestamp, 4)
        result += self.bits
        result += self.nonce
        return result

    def hash(self):
        s = self.serialize()
        h256 = hash256(s)
        return h256[::-1]
    
    def bip9(self):
        return self.version >> 29 == 0b001
    
    def bip91(self):
        return self.version >> 4 & 1 == 1
    
    def bip141(self):
        return self.version >> 1 & 1 == 1
    
    def difficulty(self):
        lowest = 0xffff * 256**(0x1d - 3)
        return lowest / self.target()
    
    def check_pow(self):
        sha = hash256(self.serialize())
        proof = little_endian_to_int(sha)
        return proof < self.target()
    
    def validate_merkle_root(self):
        # swap endianess
        hashes = [h[::-1] for h in self.hashes]
        root = merkle_root(hashes)
        return root[::-1] == self.merkle_root