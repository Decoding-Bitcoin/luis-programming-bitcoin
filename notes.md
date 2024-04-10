# notes.md

# 01 - finite fields

# 02 - elliptic curves

# 03 - elliptic curve cryptography

# 04 - serialization

note: openssl disabled ripemd160, and hashlib depends on openssl.
to enable it, use this so answer: https://stackoverflow.com/a/72508879

## SEC, compressed and uncompressed format
Standards for Efficient Cryptography (SEC) -> ECDSA public key encoding

pubkey is just a point on secp256k1. it can be either uncompressed (x and y coordinates),
or compressed (only x coordinate).

uncompressed format for P = (x,y):
```
<0x04 : PREFIX BYTE> <X COORDINATE AS BIGINT> <Y COORDINATE AS BIGINT>

65 BYTES
```

there are at most two different y values for an x value.

in a finite field, -y % p = (p - y) % p, ie: if (x,y) is a solution, then (x,p-y) is also a solution.
moreover, it holds that one y will be even and the other odd, so to encode the point in
compressed form, one needs to store the x value and the parity of y.

compressed format for P = (x,y):
```
<EVEN PARITY: 0x02 || ODD PARITY: 0x03> <X COORDINATE AS BIG ENDIAN>

33 BYTES
```

## Distinguished Encoding Rules (DER)
in order to serialize a signature, we use the TLV, or Type-Lenght-Value, scheme.
it's structured like this:
```
<0x30 : TYPE BYTE (COMPOUND VALUE)>
<0x?? : LENGHT BYTE>
    <0x02 : TYPE BYTE (VALUE)>
    <0?? : LENGHT BYTE>
    <r AS BIGINT (if r[0] >= 0x80, prepend w/ 0x00)>

    <0x02 : TYPE BYTE (VALUE)>
    <0?? : LENGHT BYTE>
    <s AS BIGINT (if s[0] >= 0x80, prepend w/ 0x00)>


