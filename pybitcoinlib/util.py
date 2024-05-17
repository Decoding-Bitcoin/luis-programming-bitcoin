from base58 import *

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3

TWO_WEEKS = 60 * 60 * 24 * 14
MAX_TARGET = 0xffff * 256**(0x1d - 3)

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

def bits_to_target(bits):
    exponent = bits[-1]
    coefficient = little_endian_to_int(bits[:-1])
    return coefficient * 256**(exponent - 3)

def target_to_bits(target):
    '''Turns a target integer back into bits, which is 4 bytes'''
    raw_bytes = target.to_bytes(32, 'big')
    # get rid of leading 0's
    raw_bytes = raw_bytes.lstrip(b'\x00')
    if raw_bytes[0] > 0x7f:
        # if the first bit is 1, we have to start with 00
        exponent = len(raw_bytes) + 1
        coefficient = b'\x00' + raw_bytes[:2]
    else:
        # otherwise, we can show the first 3 bytes
        # exponent is the number of digits in base-256
        exponent = len(raw_bytes)
        # coefficient is the first 3 digits of the base-256 number
        coefficient = raw_bytes[:3]
    # we've truncated the number after the first 3 digits of base-256
    new_bits = coefficient[::-1] + bytes([exponent])
    return new_bits

def calculate_new_bits(previous_bits, time_differential):
    if time_differential > TWO_WEEKS * 4:
        time_differential = TWO_WEEKS * 4
    if time_differential < TWO_WEEKS // 4:
        time_differential = TWO_WEEKS // 4
    new_target = bits_to_target(previous_bits) * time_differential // TWO_WEEKS
    return target_to_bits(new_target)
