from base58 import *

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3

def little_endian_to_int(b):
    return int.from_bytes(b, "little")

def int_to_little_endian(n, length):
    return n.to_bytes(length, "little")

def read_varint(s):
    '''read a variable integer from a stream'''
    i = s.read(1)[0]

    # next 2 bytes are the input size
    if i == 0xfd:
        return int.from_bytes(s.read(2), "little")
    
    # next 4 bytes are the input size
    elif i == 0xfe:
        return int.from_bytes(s.read(4), "little")
    
    # next 8 bytes are the input size
    elif i == 0xff:
        return int.from_bytes(s.read(8), "little")
    
    # the first byte is already the input size
    else:
        return i

def encode_varint(i):
    '''encode an int as a varint'''

    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return bytes([0xfd]) + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return bytes([0xfe]) + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return bytes([0xff]) + int_to_little_endian(i, 8)
    else:
        raise ValueError("integer {} is too large".format(i))
    
def h160_to_p2pkh_address(h160, testnet=False):
    if testnet:
        prefix = b'\x6f'
    else:
        prefix = b'\x00'
    return encode_base58_checksum(prefix + h160)

def h160_to_p2sh_address(h160, testnet=False):
    if testnet:
        prefix = b'\xc4'
    else:
        prefix = b'\x05'
    return encode_base58_checksum(prefix + h160)