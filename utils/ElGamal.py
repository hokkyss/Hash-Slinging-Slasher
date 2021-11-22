import random
from typing import Tuple

from utils.utils import PrimeGenerator
from utils.blockText import ArrStrToPlaintext, ciphertextToArrInt, plaintextToArrInt

class ElGamal():
	@staticmethod
	def generate():
		p = PrimeGenerator.random()

		x = random.randint(1, p - 2)
		g = random.randint(0, p - 1)
		y = pow(g, x, p)
		return [[p, g, y], [p, x]]

	@staticmethod
	def encrypt(plain_text: str, public_key: Tuple[int, int, int]) -> Tuple[str, str]:
		"""
		Encrypt the plaintext using elgamal algorithm. Public key can be generated using ElGamalKeygen
		class. Return tuple containing two ciphertext.
		"""
		# Get the public key.
		p, g, y = public_key

		# Prepare for encrypting.
		max_length = (len(str(p)) - 1) // 3
		messages_int = plaintextToArrInt(plain_text, max_length)
		print("The block is:")
		print(messages_int)

		# Encrypt using elgamal algorithm.
		complete_a = []
		complete_b = []
		for message in messages_int:
			k = random.randint(1, p - 2)
			a = pow(g, k, p)
			b = ((pow(y, k, p) * message) % p)
			complete_a.append(str(a).rjust(len(str(p)), "0"))
			complete_b.append(str(b).rjust(len(str(p)), "0"))

		# Combine a to one string and b to one string.
		complete_a = "".join(complete_a)
		complete_b = "".join(complete_b)
		return (complete_a, complete_b)

	@staticmethod
	def decrypt(cipher_text: Tuple[str, str], private_key: Tuple[int, int]) -> str:
		"""
		Decrypt the ciphertext using elgamal algorithm. Private key can be generated using ElGamalKeygen
		class. Ciphertext must be a tuple of two string (a and b). Return plaintext.
		"""
		# Get the private key.
		p, x  = private_key

		# Prepare for decrypting.
		max_length = len(str(p))
		num_alphabet = (len(str(p)) - 1) // 3
		list_a = cipher_text[0]
		list_int_a = ciphertextToArrInt(list_a, max_length)
		list_b = cipher_text[1]
		list_int_b = ciphertextToArrInt(list_b, max_length)

		# Decrypting using elgamal algorithm.
		list_ascii_plaintext = []
		for a, b in zip(list_int_a, list_int_b):
			first_equation = pow(a, p - 1 - x, p)
			plaintext_int = (b * first_equation) % p
			list_ascii_plaintext.append(str(plaintext_int).rjust(num_alphabet * 3, "0"))

		# Parse list ascii plaintext to real plaintext.
		plaintext = ArrStrToPlaintext(list_ascii_plaintext)
		return plaintext
