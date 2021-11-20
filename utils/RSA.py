# RSA Algorithm
import math
from textwrap import wrap
from typing import List

from .utils import PrimeGenerator, inverse_modulo

class RSA:
    def __init__(self, n: int, e: int, d: int) -> None:
        self.__n = n
        self.__e = e
        self.__d = d
        self.digits = len(str(n)) - 1
    
    def encrypt(self, message: str) -> str:
        """
        `message` is a hexadecimal string
        pisah jadi beberapa blok, masing-masing `self.digits - 1`
        """
        result: List[int] = []
        plain_number = int(message, 16)

        blocked = self.block_message(plain_number)
        for block in blocked:
            result.append(pow(block, self.__d, self.__n))

        return self.to_message(result)

    def decrypt(self, ciphertext: str) -> str:
        """
        `ciphertext` is a hexadecimal string
        """
        result: List[int] = []
        cipher_number = int(ciphertext, 16)

        blocked = self.block_message(cipher_number)
        for block in blocked:
            result.append(pow(block, self.__e, self.__n))

        return self.to_message(result)

    def block_message(self, number: int) -> List[int]:
        # To ensure that the block is always < n
        message = str(number)

        number_of_blocks = math.ceil(len(message) / self.digits)
        padded_text = message.zfill(number_of_blocks * self.digits)

        messages: List[int]
        messages = list(map(int, wrap(padded_text, self.digits)))
        return messages
    
    def to_message(self, blocks: List[int]) -> str:
        result: List[str] = []
        for block in blocks:
            result.append(hex(block)[2:].upper().zfill(self.digits))

        return "".join(result)

    @staticmethod
    def generate_key():
        """
        Generate public key and private key for RSA
        """
        p = PrimeGenerator.random()
        q = PrimeGenerator.random()
        n = p * q
        toi = (p - 1) * (q - 1)
        e = PrimeGenerator.random()
        d = inverse_modulo(e, toi)
        public_key = [d, n]
        private_key = [e, n]
        return [public_key, private_key]

def block_to_text(m: List[int], block_size: int) -> str:
    final_m = []
    print_format = "0" + str(block_size) + "d"
    for block in m:
        final_m.append(format(block, print_format))
    return "".join(final_m)

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

    ciphertext = RSA(n, e, d).encrypt(message)
    print("Ciphertext\t\t:", ciphertext)

    decrypted_m = RSA(n, e, d).decrypt(ciphertext)
    print("Decrypted\t\t:", decrypted_m)