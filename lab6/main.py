from os import urandom
from hashlib import md5
from lbfunc import bytes2long, modinvert, long2bytes, hexdec, CURVE_PARAMSS, CURVE_PARAMS, GOST


def public_key(curve, prv):
    return curve.mul(prv)

# sign document
def sign(curve, user_private_key, text):
    h = md5(text.encode()).digest()
    q = curve.q
    e = bytes2long(h) % q

    if e == 0:
        e = 1

    while True:
        k = bytes2long(urandom(64)) % q
        # C = kP,
        Cx, Cy = curve.mul(k) # get (x, y) - point of our eliptic curve
        # r = xc(mod q)
        r = Cx % q
        if r == 0:
            continue
        d = user_private_key * r
        k *= e
        # s = rd + ke(mod q)
        s = (d + k) % q
        if s == 0:
            continue
        break

    return long2bytes(s, 64) + long2bytes(r, 64)


def check_signature(curve, pub_key_tuple, hash, signature):

    s = bytes2long(signature[:64])
    r = bytes2long(signature[64:])

    q = curve.q
    p = curve.p

    if r <= 0 or r >= q or s <= 0 or s >= q:
        return False
    # e = z(mod q), и если e = 0, положить e = 1. Где z — целое число из 1..T
    e = bytes2long(hash) % curve.q
    if e == 0:
        e = 1
    # v = e - 1(mod q)
    v = modinvert(e, q)

    # Вычисление z1 = sv(mod q) и z2 = - rv(mod q)
    z1 = s * v % q
    z2 = q - r * v % q

    p1x, p1y = curve.mul(z1)
    q1x, q1y = curve.mul(z2, pub_key_tuple[0], pub_key_tuple[1])
    Cx = q1x - p1x
    if Cx < 0:
        Cx += p

    Cx = modinvert(Cx, p)
    z1 = q1y - p1y
    Cx = Cx * z1 % p
    Cx = Cx * Cx % p
    Cx = Cx - p1x - q1x
    Cx = Cx % p

    if Cx < 0:
        Cx += p
    R = Cx % q
    return R == r


def to_ten_str(prv):
    return bytes2long(prv[::-1])


if __name__ == '__main__':
    text = 'Hello English'
    # p, q - public key
    p, q, a, b, x, y = CURVE_PARAMS
    curve = GOST(p, q, a, b, x, y)

    # random private key
    user_private_key_d = to_ten_str(urandom(32))# get random numbers string with len==32, hex format and convert to ten format string

    signatured_text = sign(curve, user_private_key_d, text)

    print("Signatured message: {}".format(signatured_text))

    pub_key_tuple = public_key(curve, user_private_key_d)

    is_true = check_signature(curve,
                              pub_key_tuple,
                              md5((text).encode()).digest(),
                              # md5((text + 'added part').encode()).digest(),
                              signatured_text)

    print("Message: {}".format(text))
    if is_true:
        print("ECP is confirmed")
    else:
        print("ECP is not confirmed")