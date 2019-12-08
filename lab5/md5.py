class hmac_MD5:
    def __init__(self, arg=None):
        # step 3, from wiki, buffer initialization
        self.A = 0x67452301; self.B = 0xEFCDAB89; self.C = 0x98BADCFE; self.D = 0x10325476
        self.hash(arg)
        self.digest_size = 16

    def _to_binary_str(self, string):
        return ''.join("{:08b}".format(byte) for byte in bytearray(string.encode('utf-8')))

    def _split_to_blocks(self, message, n):
        return [message[i:i + n] for i in range(0, len(message), n)]

    def _create_word_array(self, message, messageLength, finalBlock):
        """Primes the 16-bit words for the main function and returns as an
        array. Repeated calls with the finalBlock parameter will determine if we
        need to put the length and 0 last."""
        message = self._split_to_blocks(message, 32)
        wordArray = [0] * 16
        wordIndex = 0
        for word in message:
            bytes = self._split_to_blocks(word, 8)
            tempByte = 0
            powers = 0

            for byte in bytes:
                tempByte = wordArray[wordIndex]
                tempByte = tempByte | int(byte, 2) << powers
                powers += 8
                wordArray[wordIndex] = tempByte

            wordIndex += 1
            powers = 0

        # correct last two bytes if we're on the final block
        if finalBlock:
            wordArray[-2] = messageLength << 3
            wordArray[-1] = messageLength >> 2
        return wordArray

    # Viravnivanie potoka: Adds padding to binary string be congruent to 448 mod 512
    def step_1(self, bstring):
        padded = ''
        messageLength = len(bstring)
        bstring += "1"
        while (len(bstring) % 512) != 448:
            bstring += "0"
        padded += bstring + self.step_2_padding_64B(messageLength)
        return padded

    # Add length to message
    def step_2_padding_64B(self, length):
        """Creates a little-endian 64-bit representation of the message length"""
        s = bin(length).replace('b', '0')
        # If we reach 64-bit overflow
        if len(s) > 64:
            return '0' + '1' * 63
        padded = "0" * (64 - len(s))
        padded += s[::-1]  # reverse length byte first to preserve correct order
        return padded[::-1]

    # Convert 16x hash to binnary string A, B, C, D, (revert bytes(A)) + revert bytes(B)) + ...
    def zip_convert(self):
        res = b''
        buffers = [self.A, self.B, self.C, self.D]

        for buffer in buffers:
            bufferbytes = []
            b = bin(buffer).replace('b', '0')
            b = "0" * (34 - len(b)) + b  # pad leading zero if missing

            bufferbytes.append(int(b[2:10], 2))
            bufferbytes.append(int(b[10:18], 2))
            bufferbytes.append(int(b[18:26], 2))
            bufferbytes.append(int(b[26:34], 2))

            res += bytes([bufferbytes[3]])
            res += bytes([bufferbytes[2]])
            res += bytes([bufferbytes[1]])
            res += bytes([bufferbytes[0]])
        # print(res)
        return res

    # get hash
    def hash(self, message):
        messageLength = len(message.encode('utf-8'))
        parts = self._split_to_blocks(self.step_1(self._to_binary_str(message)), 512)

        R11, R12, R13, R14 = 7, 12, 17, 22
        R21, R22, R23, R24 = 5, 9, 14, 20
        R31, R32, R33, R34 = 4, 11, 16, 23
        R41, R42, R43, R44 = 6, 10, 15, 21

        for part in parts:
            # print(len(part)) - 512 bit
            w_s = self._create_word_array(part, messageLength, parts.index(part) == len(parts) - 1)

            a_temp, b_temp, c_temp, d_temp = A, B, C, D = self.A, self.B, self.C, self.D

            def F_func(x, y, z):
                return (x & y) | ((~x) & z)

            a_temp = Op(F_func, a_temp, b_temp, c_temp, d_temp, w_s[0], R11, 0xD76AA478)
            d_temp = Op(F_func, d_temp, a_temp, b_temp, c_temp, w_s[1], R12, 0xE8C7B756)
            c_temp = Op(F_func, c_temp, d_temp, a_temp, b_temp, w_s[2], R13, 0x242070DB)
            b_temp = Op(F_func, b_temp, c_temp, d_temp, a_temp, w_s[3], R14, 0xC1BDCEEE)
            a_temp = Op(F_func, a_temp, b_temp, c_temp, d_temp, w_s[4], R11, 0xF57C0FAF)
            d_temp = Op(F_func, d_temp, a_temp, b_temp, c_temp, w_s[5], R12, 0x4787C62A)
            c_temp = Op(F_func, c_temp, d_temp, a_temp, b_temp, w_s[6], R13, 0xA8304613)
            b_temp = Op(F_func, b_temp, c_temp, d_temp, a_temp, w_s[7], R14, 0xFD469501)
            a_temp = Op(F_func, a_temp, b_temp, c_temp, d_temp, w_s[8], R11, 0x698098D8)
            d_temp = Op(F_func, d_temp, a_temp, b_temp, c_temp, w_s[9], R12, 0x8B44F7AF)
            c_temp = Op(F_func, c_temp, d_temp, a_temp, b_temp, w_s[10], R13, 0xFFFF5BB1)
            b_temp = Op(F_func, b_temp, c_temp, d_temp, a_temp, w_s[11], R14, 0x895CD7BE)
            a_temp = Op(F_func, a_temp, b_temp, c_temp, d_temp, w_s[12], R11, 0x6B901122)
            d_temp = Op(F_func, d_temp, a_temp, b_temp, c_temp, w_s[13], R12, 0xFD987193)
            c_temp = Op(F_func, c_temp, d_temp, a_temp, b_temp, w_s[14], R13, 0xA679438E)
            b_temp = Op(F_func, b_temp, c_temp, d_temp, a_temp, w_s[15], R14, 0x49B40821)

            def G_func(x, y, z):
                return (x & z) | (y & (~z))

            a_temp = Op(G_func, a_temp, b_temp, c_temp, d_temp, w_s[1], R21, 0xF61E2562)
            d_temp = Op(G_func, d_temp, a_temp, b_temp, c_temp, w_s[6], R22, 0xC040B340)
            c_temp = Op(G_func, c_temp, d_temp, a_temp, b_temp, w_s[11], R23, 0x265E5A51)
            b_temp = Op(G_func, b_temp, c_temp, d_temp, a_temp, w_s[0], R24, 0xE9B6C7AA)
            a_temp = Op(G_func, a_temp, b_temp, c_temp, d_temp, w_s[5], R21, 0xD62F105D)
            d_temp = Op(G_func, d_temp, a_temp, b_temp, c_temp, w_s[10], R22, 0x02441453)
            c_temp = Op(G_func, c_temp, d_temp, a_temp, b_temp, w_s[15], R23, 0xD8A1E681)
            b_temp = Op(G_func, b_temp, c_temp, d_temp, a_temp, w_s[4], R24, 0xE7D3FBC8)
            a_temp = Op(G_func, a_temp, b_temp, c_temp, d_temp, w_s[9], R21, 0x21E1CDE6)
            d_temp = Op(G_func, d_temp, a_temp, b_temp, c_temp, w_s[14], R22, 0xC33707D6)
            c_temp = Op(G_func, c_temp, d_temp, a_temp, b_temp, w_s[3], R23, 0xF4D50D87)
            b_temp = Op(G_func, b_temp, c_temp, d_temp, a_temp, w_s[8], R24, 0x455A14ED)
            a_temp = Op(G_func, a_temp, b_temp, c_temp, d_temp, w_s[13], R21, 0xA9E3E905)
            d_temp = Op(G_func, d_temp, a_temp, b_temp, c_temp, w_s[2], R22, 0xFCEFA3F8)
            c_temp = Op(G_func, c_temp, d_temp, a_temp, b_temp, w_s[7], R23, 0x676F02D9)
            b_temp = Op(G_func, b_temp, c_temp, d_temp, a_temp, w_s[12], R24, 0x8D2A4C8A)


            def H_func(x, y, z):
                return x ^ y ^ z


            a_temp = Op(H_func, a_temp, b_temp, c_temp, d_temp, w_s[5], R31, 0xFFFA3942)
            d_temp = Op(H_func, d_temp, a_temp, b_temp, c_temp, w_s[8], R32, 0x8771F681)
            c_temp = Op(H_func, c_temp, d_temp, a_temp, b_temp, w_s[11], R33, 0x6D9D6122)
            b_temp = Op(H_func, b_temp, c_temp, d_temp, a_temp, w_s[14], R34, 0xFDE5380C)
            a_temp = Op(H_func, a_temp, b_temp, c_temp, d_temp, w_s[1], R31, 0xA4BEEA44)
            d_temp = Op(H_func, d_temp, a_temp, b_temp, c_temp, w_s[4], R32, 0x4BDECFA9)
            c_temp = Op(H_func, c_temp, d_temp, a_temp, b_temp, w_s[7], R33, 0xF6BB4B60)
            b_temp = Op(H_func, b_temp, c_temp, d_temp, a_temp, w_s[10], R34, 0xBEBFBC70)
            a_temp = Op(H_func, a_temp, b_temp, c_temp, d_temp, w_s[13], R31, 0x289B7EC6)
            d_temp = Op(H_func, d_temp, a_temp, b_temp, c_temp, w_s[0], R32, 0xEAA127FA)
            c_temp = Op(H_func, c_temp, d_temp, a_temp, b_temp, w_s[3], R33, 0xD4EF3085)
            b_temp = Op(H_func, b_temp, c_temp, d_temp, a_temp, w_s[6], R34, 0x04881D05)
            a_temp = Op(H_func, a_temp, b_temp, c_temp, d_temp, w_s[9], R31, 0xD9D4D039)
            d_temp = Op(H_func, d_temp, a_temp, b_temp, c_temp, w_s[12], R32, 0xE6DB99E5)
            c_temp = Op(H_func, c_temp, d_temp, a_temp, b_temp, w_s[15], R33, 0x1FA27CF8)
            b_temp = Op(H_func, b_temp, c_temp, d_temp, a_temp, w_s[2], R34, 0xC4AC5665)

            def I_func(x, y, z):
                return y ^ (x | (~z))


            a_temp = Op(I_func, a_temp, b_temp, c_temp, d_temp, w_s[0], R41, 0xF4292244)
            d_temp = Op(I_func, d_temp, a_temp, b_temp, c_temp, w_s[7], R42, 0x432AFF97)
            c_temp = Op(I_func, c_temp, d_temp, a_temp, b_temp, w_s[14], R43, 0xAB9423A7)
            b_temp = Op(I_func, b_temp, c_temp, d_temp, a_temp, w_s[5], R44, 0xFC93A039)
            a_temp = Op(I_func, a_temp, b_temp, c_temp, d_temp, w_s[12], R41, 0x655B59C3)
            d_temp = Op(I_func, d_temp, a_temp, b_temp, c_temp, w_s[3], R42, 0x8F0CCC92)
            c_temp = Op(I_func, c_temp, d_temp, a_temp, b_temp, w_s[10], R43, 0xFFEFF47D)
            b_temp = Op(I_func, b_temp, c_temp, d_temp, a_temp, w_s[1], R44, 0x85845DD1)
            a_temp = Op(I_func, a_temp, b_temp, c_temp, d_temp, w_s[8], R41, 0x6FA87E4F)
            d_temp = Op(I_func, d_temp, a_temp, b_temp, c_temp, w_s[15], R42, 0xFE2CE6E0)
            c_temp = Op(I_func, c_temp, d_temp, a_temp, b_temp, w_s[6], R43, 0xA3014314)
            b_temp = Op(I_func, b_temp, c_temp, d_temp, a_temp, w_s[13], R44, 0x4E0811A1)
            a_temp = Op(I_func, a_temp, b_temp, c_temp, d_temp, w_s[4], R41, 0xF7537E82)
            d_temp = Op(I_func, d_temp, a_temp, b_temp, c_temp, w_s[11], R42, 0xBD3AF235)
            c_temp = Op(I_func, c_temp, d_temp, a_temp, b_temp, w_s[2], R43, 0x2AD7D2BB)
            b_temp = Op(I_func, b_temp, c_temp, d_temp, a_temp, w_s[9], R44, 0xEB86D391)

            A = (a_temp + A) & 0xffffffff
            B = (b_temp + B) & 0xffffffff
            C = (c_temp + C) & 0xffffffff
            D = (d_temp + D) & 0xffffffff

            self.A = A
            self.B = B
            self.C = C
            self.D = D


def md5(arg=None):
    return hmac_MD5(arg)


def F_func(x, y, z):
    return (x & y) | ((~x) & z)

def G_func(x, y, z):
    return (x & z) | (y & (~z))

def H_func(x, y, z):
    return x ^ y ^ z

def I_func(x, y, z):
    return y ^ (x | (~z))

def shl(x, n):
    return (x << n) | (x >> (32 - n))

def Op(function, a, b, c, d, x, s, t):
    r = (a + function(b, c, d) + x + t) & 0xffffffff
    r = shl(r, s) & 0xffffffff
    r = r + b
    return r & 0xffffffff  # Keep r unsigned

