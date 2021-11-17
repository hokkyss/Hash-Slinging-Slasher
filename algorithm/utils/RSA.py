# RSA Algorithm

import random
from textwrap import wrap
from typing import List

from .utils import PrimeGenerator, pow_mod, inverse_modulo

def text_to_block(message: str, n: int) -> List[int]:
    digits: int = len(str(n))
    messages: List[int]
    try:
        messages = list(map(int, wrap(message, digits)))
        for block in messages:
            if (block >= n) or (block < 0):
                raise ValueError
    except:
        messages = list(map(int, wrap(message, digits - 1)))
    return messages

def block_to_text(m: List[int], block_size: int) -> str:
    final_m = []
    print_format = "0" + str(block_size) + "d"
    for block in m:
        final_m.append(format(block, print_format))
    return "".join(final_m)

# Encrypt the ciphertext with RSA Algorithm
def rsa_encryption(message: str, n: int, e: int) -> str:
    block_size = len(str(n))
    # m = text_to_block(message, block_size)
    m = text_to_block(message, n)
    c = []
    for block in m:
        ci = pow_mod(block, e, n)
        c.append(ci)
    return block_to_text(c, block_size)
    # return ''.join(list(map(str, c)))

# Decrypt the ciphertext with RSA Algorithm
def rsa_decryption(ciphertext: str, n: int, d: int) -> str:
    # block_size = len(str(n))
    # c = text_to_block(ciphertext, block_size)
    c = text_to_block(ciphertext, n)
    m = []
    for block in c:
        mi = pow_mod(block, d, n)
        m.append(mi)
    # return block_to_text(m, block_size)
    return ''.join(list(map(str, m)))

# Generate rsa key
def generate_rsa_key():
    p = PrimeGenerator.random()
    q = PrimeGenerator.random()
    n = p * q
    toi = (p - 1) * (q - 1)
    e = PrimeGenerator.random()
    d = inverse_modulo(e, toi)
    public_key = [e, n]
    private_key = [d, n]
    return [public_key, private_key]

# Main program to test
if (__name__ == "__main__"):
    # p = int(input("Nilai p: "))
    # q = int(input("Nilai q: "))
    p = PrimeGenerator.random()
    q = PrimeGenerator.random()
    n = p * q
    toi = (p - 1) * (q - 1)
    e = PrimeGenerator.random()

    # e = int(input("Nilai e: "))
    d = inverse_modulo(e, toi)
    print("Nilai p dan q\t\t:", p, ",", q)
    print("Nilai n dan toi\t\t:", n, ",", toi)
    print("Public key (e, n)\t:", e, ",", n)
    print("Private key (d, n)\t:", d, ",", n)

    message = "7041111140011080204"
    message = "99999999999999999999"
    # message = input()
    print("Message\t\t\t:", message)

    ciphertext = rsa_encryption(message, n, e)
    print("Ciphertext\t\t:", ciphertext)

    decrypted_m = rsa_decryption(ciphertext, n, d)
    print("Decrypted\t\t:", decrypted_m)