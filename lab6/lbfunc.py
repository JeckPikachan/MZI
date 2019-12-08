from os import urandom

from codecs import getdecoder
from codecs import getencoder
from sys import version_info
from hashlib import md5

CURVE_PARAMSS = [
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD97",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF6C611070995AD10045841B09B761B893",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFD94",
    "00000000000000000000000000000000000000000000000000000000000000a6",
    "0000000000000000000000000000000000000000000000000000000000000001",
    "8D91E471E0989CDA27DF505A453F2B7635294F2DDF23E3B122ACC99C9E9F1E14",
]

def hexdec(data):
    """Decode hexadecimal
    """
    _hexdecoder = getdecoder("hex")
    return _hexdecoder(data)[0]


def hexenc(data):
    """Encode hexadecimal
    """
    _hexencoder = getencoder("hex")
    return _hexencoder(data)[0].decode("ascii")


def strxor(a, b):
    """ XOR of two strings

    This function will process only shortest length of both strings,
    ignoring remaining one.
    """
    mlen = min(len(a), len(b))
    a, b, xor = bytearray(a), bytearray(b), bytearray(mlen)
    for i in range(mlen):
        xor[i] = a[i] ^ b[i]

    return bytes(xor)


def bytes2long(raw):
    """ Deserialize big-endian bytes into long number

    :param bytes raw: binary string
    :returns: deserialized long number
    :rtype: int
    """
    return int(hexenc(raw), 16)


def long2bytes(n, size=32):
    """ Serialize long number into big-endian bytestring

    :param long n: long number
    :returns: serialized bytestring
    :rtype: bytes
    """
    res = hex(int(n))[2:].rstrip("L")
    if len(res) % 2 != 0:
        res = "0" + res
    s = hexdec(res)
    if len(s) != size:
        s = (size - len(s)) * b"\x00" + s
    return s


def modinvert(a, n):
    """ Modular multiplicative inverse

    :returns: inverse number. -1 if it does not exist

    Realization is taken from:
    https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    """
    if a < 0:
        return n - modinvert(-a, n)
    t, newt = 0, 1
    r, newr = n, a
    while newr != 0:
        quotinent = r // newr
        t, newt = newt, t - quotinent * newt
        r, newr = newr, r - quotinent * newr
    if r > 1:
        return -1
    if t < 0:
        t = t + n
    return t

CURVE_PARAMS = [hexdec(param) for param in CURVE_PARAMSS]

class GOST(object):
    def __init__(self, p, q, a, b, x, y):
        self.p = bytes2long(p)
        self.q = bytes2long(q)
        self.a = bytes2long(a)
        self.b = bytes2long(b)
        self.x = bytes2long(x)
        self.y = bytes2long(y)

        # validate curve params
        r1 = self.y * self.y % self.p
        r2 = ((self.x * self.x + self.a) * self.x + self.b) % self.p
        if r2 < 0:
            r2 += self.p
        if r1 != r2:
            raise ValueError("Invalid parameters")

    def _pos(self, v):
        if v < 0:
            return v + self.p
        return v

    def _add(self, p1x, p1y, p2x, p2y):
        if p1x == p2x and p1y == p2y:
            m = ((3 * p1x * p1x + self.a) * modinvert(2 * p1y, self.p)) % self.p
        else:
            mx = self._pos(p2x - p1x) % self.p
            my = self._pos(p2y - p1y) % self.p
            m = (my * modinvert(mx, self.p)) % self.p
        mx = self._pos(m * m - p1x - p2x) % self.p
        my = self._pos(m * (p1x - mx) - p1y) % self.p
        return mx, my

    def mul(self, stepen, x=None, y=None):
        x = x or self.x
        y = y or self.y
        tx = x
        ty = y
        stepen -= 1
        while stepen != 0:
            if stepen & 1 == 1:
                tx, ty = self._add(tx, ty, x, y)
            stepen = stepen >> 1
            x, y = self._add(x, y, x, y)
        return tx, ty


def hexdec(data):
    """Decode hexadecimal
    """
    _hexdecoder = getdecoder("hex")
    return _hexdecoder(data)[0]


def hexenc(data):
    """Encode hexadecimal
    """
    _hexencoder = getencoder("hex")
    return _hexencoder(data)[0].decode("ascii")


def strxor(a, b):
    """ XOR of two strings

    This function will process only shortest length of both strings,
    ignoring remaining one.
    """
    mlen = min(len(a), len(b))
    a, b, xor = bytearray(a), bytearray(b), bytearray(mlen)
    for i in range(mlen):
        xor[i] = a[i] ^ b[i]

    return bytes(xor)


def bytes2long(raw):
    """ Deserialize big-endian bytes into long number

    :param bytes raw: binary string
    :returns: deserialized long number
    :rtype: int
    """
    return int(hexenc(raw), 16)


def long2bytes(n, size=32):
    """ Serialize long number into big-endian bytestring

    :param long n: long number
    :returns: serialized bytestring
    :rtype: bytes
    """
    res = hex(int(n))[2:].rstrip("L")
    if len(res) % 2 != 0:
        res = "0" + res
    s = hexdec(res)
    if len(s) != size:
        s = (size - len(s)) * b"\x00" + s
    return s


def modinvert(a, n):
    """ Modular multiplicative inverse

    :returns: inverse number. -1 if it does not exist

    Realization is taken from:
    https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
    """
    if a < 0:
        return n - modinvert(-a, n)
    t, newt = 0, 1
    r, newr = n, a
    while newr != 0:
        quotinent = r // newr
        t, newt = newt, t - quotinent * newt
        r, newr = newr, r - quotinent * newr
    if r > 1:
        return -1
    if t < 0:
        t = t + n
    return t