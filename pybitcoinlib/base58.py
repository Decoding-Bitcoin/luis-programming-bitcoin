from hash import hash256

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def encode_base58(s):
    count = 0
    # determine how many 0x00's are in the front
    for c in s:
        if c == 0:
            count += 1
        else:
            break

    num = int.from_bytes(s, "big")
    prefix = "1" * count
    result = ""

    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    
    return prefix + result

def encode_base58_checksum(b):
    return encode_base58(b + hash256(b)[:4])

def decode_base58(s):
    num = 0
    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)
    
    combined = num.to_bytes(25, "big")

    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError("bad address: {} {}".format(checksum, hash256(combined[:-4])[:4]))
    return combined[1:-4]