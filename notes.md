# programming bitcoin

# 01 - finite fields
a finite field is defined as a finite set of numbers and the ops (+) and (*) which must 
satisfy the below:

- if _a_ and _b_ are in the set, then (_a + b_) and (_a * b_) are also in the set. this is the
definition of a _closed set_;
- 0 belongs to the set, and behaves such that _a + 0 = a_. this is the _additive_ identity;
- 1 belongs to the set, and behaves such that _a * 1 = a_. this is the _multiplicative_ identity;
- if _a_ belongs to the set, the _-a_ is also in the set, such that _a + (-a) = a_. this is the 
additive inverse;
- if _a_ belongs to the set and is not 0, _a^-1_ is in the set, such that _a * a^-1 = 1_. 
this is the multiplicative inverse.

the size, or order, of a set, is the number of elements in it, denoted as _p_.

if a set has order p=7, then the set will be `F_7 = {0, 1, 2, 3, 4, 5, 6}`

in order to stay within the field, all operations must be done `mod p`. for p=7,
they would look like this:

```
5 + 3 = (5 + 3) mod 7 = 1

21 * 42 = (21 * 42) mod 7 = 882 mod 7 = 0
```


# 02 - elliptic curves
an elliptic curve is a curve defined by this general formula 

_y^2 = x^3 + ax + b_

## point addition
it's very useful to be able to add points on an elliptic curve. however,
to add the points in an EC, you don't just add up the x and y coordinates.

there is something called point at infinity `I`, such that

`I + A = A [identity]`

this is the identity point. from `I` follows that

`A + (-A) = I [invertibility]`

### when x1 != x2
P1 = (x1,y1), P2 = (x2,y2), P3 = (x3,y3)

P1 + P2 = P3

s = (y2 - y1) / (x2 - x1)

x3 = s^2 - x1 - x2

y3 = s(x1 - x3) - y1

### when P1 = P2
P1 = (x1,y1), P3 = (x3,y3)

P1 + P1 = P3

s = (3 * x1^2 + a) / 2 * y1

x3 = s^2 - 2x

y3 = s(x1 - x3) - y1

# 03 - elliptic curve cryptography
bitcoin uses an elliptic curve called secp256k1, defined by `y2 = x3 + 7`. but this curve
is not over the infinite field of reals, but over a finite field. graphing this function 
will show a bunch of points scattered, and not a curve as expected.

point addition is non-linear, doing point division is extremely expensive, discrete log problem

```
secp256k1 is defined by these constants:

a = 0
b = 7

p = 2^256 - 2^32 - 977

Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8

n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
```

G = (Gx,Gy) is the generator point, from which all other points are "derived"

## public key cryptography
pubkey crypto relies on the cost assymetry in performing point multiplication vs point division

the key operation is `P = eG`, where `e` is a secret. computing `P` is very easy if you know `e` and
`G`, but very hard (like incredibly hard, intractably hard) to compute `e` knowing `P` and `G`. in
short:

`P = eG (easy)`

`e = P/G (hard)`

## signing and verification
bitcoin uses ECDSA (elliptic curve digital signing algorithm).

eG = P

k is a 256-bit random value called nonce (number used once)

kG = R -> Rx = r (r as in random)

uG + vP = kG (u,v != 0)

vP = (k - u)G

P = ((k - u)/v)G

eG = ((k - u)/v)G

e = (k - u)/v

to find a (u, v) that satisfies the above requires knowing `e` in the first place.

z = HASH(message)

u = z/v / v = r/s

so u has to do with the message being signed, and r has to do with the nonce we chose,
but we still need s:

uG + vP = R = kG
uG + veG = kG
u + ve = k
z/s + re/s = k
(z + re)/s = k
s = (z + re)/k

out of this we get an (r, s) tuple

to verify a signature, we do this:

uG + vP = (z/s)G + (re/s)G = ((z+re)/s)G = ((z + re)/((z + re)/k))G = kG = (r,y)


# 04 - serialization

note: openssl disabled ripemd160, and hashlib depends on openssl.
to enable it, follow this stack overflow answer: https://stackoverflow.com/a/72508879

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
<EVEN PARITY: 0x02 || ODD PARITY: 0x03> <X COORDINATE AS BIGINT>

33 BYTES
```

## Distinguished Encoding Rules (DER)
in order to serialize a signature, we use the TLV, or Type-Lenght-Value, scheme.
it's structured like this:
```
<0x30 : TYPE BYTE (COMPOUND VALUE)>
<0x?? : LENGHT BYTE>
    <0x02 : TYPE BYTE (VALUE)>
    <0x?? : LENGHT BYTE>
    <r AS BIGINT (if r[0] >= 0x80, prepend w/ 0x00)>

    <0x02 : TYPE BYTE (VALUE)>
    <0x?? : LENGHT BYTE>
    <s AS BIGINT (if s[0] >= 0x80, prepend w/ 0x00)>


