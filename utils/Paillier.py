# Paillier Algorithm

import random
from textwrap import wrap
from typing import List

from .utils import PrimeGenerator, lcm, gcd

# Get the L value based on x and n
def L(x, n):
    return int((x - 1) / n)

# Get the miu value based on g, lamda, and n value
def get_miu(g: int, lamda: int, n: int):
    x = pow(g, lamda, n ** 2)
    return pow(L(x, n), -1, n)

# Encrypt the message / plaintext with Paillier Algorithm
def paillier_encryption(message: str, g: int, n: int) -> str:
    m = int(message)
    r = PrimeGenerator.random_below(n)
    return str(pow(pow(g, m, n * n) * pow(r, n, n * n), 1, n * n))

# Decrypt the ciphertext with Paillier Algorithm
def paillier_decryption(ciphertext: str, lamda: int, miu: int, n: int) -> str:
    c = int(ciphertext)
    x = pow(c, lamda, n ** 2)
    return str(pow(L(x, n) * miu, 1, n))

# Generate paillier key
def generate_paillier_key():
    p = PrimeGenerator.random()
    q = PrimeGenerator.random()
    n = p * q
    toi = (p - 1) * (q - 1)
    while (gcd(n, toi) != 1):
        p = PrimeGenerator.random()
        q = PrimeGenerator.random()
        n = p * q
        toi = (p - 1) * (q - 1)

    lamda = lcm(p - 1, q - 1)
    g = n + 1
    miu = get_miu(g, lamda, n)
    public_key = [g, n]
    private_key = [lamda, miu, n]
    return [public_key, private_key]

# Main program to test
if (__name__ == "__main__"):
    all_key = generate_paillier_key()
    g = all_key[0][0]
    n = all_key[0][1]
    lamda = all_key[1][0]
    miu = all_key[1][0]
    miu = get_miu(g, lamda, n)
    print("Public key\t\t:", g, ":", n)
    print("Private key\t\t:", lamda, ",", miu, ",", n)

    m = random.randint(0, n)
    message = str(m)
    print("Message\t\t\t:", message)

    ciphertext = paillier_encryption(m, g, n)
    print("Cipherteks\t\t:", ciphertext)

    decrypted_m = paillier_decryption(ciphertext, lamda, miu, n)
    print("Decrypted\t\t:", decrypted_m)