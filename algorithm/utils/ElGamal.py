# ElGamal Algorithm
from typing import List, Tuple
from random import randint

from .utils import PrimeGenerator, inverse_modulo, message_blocking, pow_mod

class ElGamal:
    @staticmethod
    def encrypt(m: List[int], public_key: Tuple[int, int, int]) -> List[Tuple[int, int]]:
        (p, g, y) = public_key

        k = randint(0, p - 1)

        result: List[Tuple[int, int]] = []
        for block in m:
            a = pow_mod(g, k, p)
            b = (pow_mod(y, k, p) * block) % p
            result.append((a, b))

        return result

    @staticmethod
    def decrypt(m: List[Tuple[int, int]], private_key: Tuple[int, int]) -> List[int]:
        (p, x) = private_key

        result: List[int] = []

        for (a, b) in m:
            a = a % p; b = b % p

            inverse = inverse_modulo(pow_mod(a, x, p), p)
            result.append((b * inverse) % p)
        return result

    @staticmethod
    def generate_key():
        p = PrimeGenerator.random()

        x = randint(1, p - 2)
        g = randint(0, p - 1)
        y = pow_mod(g, x, p)
        return [[p, g, y], [p, x]]

if __name__ == "__main__":
    print("p is public")
    p = int(input("p = any prime number = "))

    print("x is private. 1 <= x <=", p - 2)
    x = int(input("x = "))

    print("g is public. g <", p)
    g = int(input("g = "))

    print("y is public. y =", pow_mod(g, x, p))
    y = pow_mod(g, x, p)

    print("public key: (p, g, y) =", (p, g, y))
    # private key = x

    m = input("message to be encrypted = ")
    (m, ) = message_blocking(x, m, p)

    encrypted = ElGamal.encrypt(m, public_key=(p, g, y))
    print(encrypted)

    decrypted = ElGamal.decrypt(encrypted, (p, x))
    print(decrypted)