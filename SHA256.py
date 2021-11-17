import utils as u
from utils.RSA import rsa_encryption, rsa_decryption


class SHA256:
    def __init__(self, message):
        # h is initial hash value, which is the first 32 bits of the fractional parts of the
        # square roots of the first 8 primes.
        self.h = [
            '0x6a09e667', '0xbb67ae85', '0x3c6ef372', '0xa54ff53a', '0x510e527f',
            '0x9b05688c', '0x1f83d9ab', '0x5be0cd19'
        ]

        # k is the first 32 bits of the fractional parts of the cubic roots of the
        # first 64 prime numbers.
        self.K = [
            '0x428a2f98', '0x71374491', '0xb5c0fbcf', '0xe9b5dba5', '0x3956c25b', '0x59f111f1',
            '0x923f82a4', '0xab1c5ed5', '0xd807aa98', '0x12835b01', '0x243185be', '0x550c7dc3',
            '0x72be5d74', '0x80deb1fe', '0x9bdc06a7', '0xc19bf174', '0xe49b69c1', '0xefbe4786',
            '0x0fc19dc6', '0x240ca1cc', '0x2de92c6f', '0x4a7484aa', '0x5cb0a9dc', '0x76f988da',
            '0x983e5152', '0xa831c66d', '0xb00327c8', '0xbf597fc7', '0xc6e00bf3', '0xd5a79147',
            '0x06ca6351', '0x14292967', '0x27b70a85', '0x2e1b2138', '0x4d2c6dfc', '0x53380d13',
            '0x650a7354', '0x766a0abb', '0x81c2c92e', '0x92722c85', '0xa2bfe8a1', '0xa81a664b',
            '0xc24b8b70', '0xc76c51a3', '0xd192e819', '0xd6990624', '0xf40e3585', '0x106aa070',
            '0x19a4c116', '0x1e376c08', '0x2748774c', '0x34b0bcb5', '0x391c0cb3', '0x4ed8aa4a',
            '0x5b9cca4f', '0x682e6ff3', '0x748f82ee', '0x78a5636f', '0x84c87814', '0x8cc70208',
            '0x90befffa', '0xa4506ceb', '0xbef9a3f7', '0xc67178f2',
        ]

        # Message that want to be hash.
        self.message = message

    def __initializer(self, values):
        byte_values = [bin(int(val, 16))[2:] for val in values]

        words = []
        for byte_value in byte_values:
            word = [int(bit) for bit in byte_value]
            words.append(u.pad_with_zero(word, 32, 'left'))

        return words

    def __preprocess_message(self):
        bit_list = u.string_to_bit_list(self.message)
        bit_list_length = len(bit_list)
        message_length_bit = [
            int(bit) for bit in bin(bit_list_length)[2:].zfill(64)
        ]

        bit_list.append(1)

        if(bit_list_length < 448):
            bit_list = u.pad_with_zero(bit_list, 448, 'right')
            bit_list = bit_list + message_length_bit

            return [bit_list]

        if(bit_list_length == 448):
            bit_list = u.pad_with_zero(bit_list, 960, 'right')
            bit_list = bit_list + message_length_bit

            return u.chunk_bits(list(bit_list), 512)

        if(bit_list_length > 448):
            expected_length = bit_list_length
            while(expected_length % 512 != 0):
                expected_length += 1

            bit_list = u.pad_with_zero(bit_list, expected_length - 64, 'right')
            bit_list = bit_list + message_length_bit

            return u.chunk_bits(list(bit_list), 512)

    def hash(self):
        k = self.__initializer(self.K)
        h0, h1, h2, h3, h4, h5, h6, h7 = self.__initializer(self.h)
        chunks = self.__preprocess_message()

        for chunk in chunks:
            w = u.chunk_bits(chunk, 32)
            for _ in range(48):
                w.append(32 * [0])
            for i in range(16, 64):
                s0 = u.XORXOR(u.rotr(w[i-15], 7),
                              u.rotr(w[i-15], 18), u.shr(w[i-15], 3))
                s1 = u.XORXOR(u.rotr(w[i-2], 17),
                              u.rotr(w[i-2], 19), u.shr(w[i-2], 10))
                w[i] = u.add(u.add(u.add(w[i-16], s0), w[i-7]), s1)
            a = h0
            b = h1
            c = h2
            d = h3
            e = h4
            f = h5
            g = h6
            h = h7
            for j in range(64):
                S1 = u.XORXOR(u.rotr(e, 6), u.rotr(e, 11), u.rotr(e, 25))
                ch = u.XOR(u.AND(e, f), u.AND(u.NOT(e), g))
                temp1 = u.add(u.add(u.add(u.add(h, S1), ch), k[j]), w[j])
                S0 = u.XORXOR(u.rotr(a, 2), u.rotr(a, 13), u.rotr(a, 22))
                m = u.XORXOR(u.AND(a, b), u.AND(a, c), u.AND(b, c))
                temp2 = u.add(S0, m)
                h = g
                g = f
                f = e
                e = u.add(d, temp1)
                d = c
                c = b
                b = a
                a = u.add(temp1, temp2)
            h0 = u.add(h0, a)
            h1 = u.add(h1, b)
            h2 = u.add(h2, c)
            h3 = u.add(h3, d)
            h4 = u.add(h4, e)
            h5 = u.add(h5, f)
            h6 = u.add(h6, g)
            h7 = u.add(h7, h)

        digest = ''
        for val in [h0, h1, h2, h3, h4, h5, h6, h7]:
            digest += u.bit_list_to_hex(val)
        return digest


if __name__ == "__main__":
    sha256 = SHA256('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')
    res = int(sha256.hash())
    print(res)
    res1 = int(rsa_encryption(str(res), 6280509711293,9546737))%6280509711293
    print(res1)