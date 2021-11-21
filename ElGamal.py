import os
import random
import utils
import sympy

from datetime import datetime
from typing import Tuple

from utils.blockText import ArrStrToPlaintext, ciphertextToArrInt, plaintextToArrInt


class ElGamalKeygen:
	"""
	A class used for generating public and private key from ElGamal algorithm.
	"""

	def __init__(self, public_key:Tuple[int, int, int]=(0,0,0), private_key:Tuple[int,int]=(0,0)) -> None:
		"""
		Constructor for ElGamalKeygen class.
		"""
		self.public_key = public_key
		self.private_key = private_key
		self.math = utils.Math()

	def generateKey(self, is_random:bool=True, key_size:int=28, p:int=0) -> None:
		"""
		Generate public and private key from parameter given. 
		"""
		# If generate random key. 
		if (is_random):
			# Get the requirement element.
			p = sympy.randprime(pow(2, key_size - 1) + 1, pow(2, key_size) - 1)
	
		# Validation.
		if(not is_random):
			if (not self.math.isPrime(p) or len(str(p)) <= 3):
				raise Exception("P must be a prime number and greater than 1000")
		
		# Get another element. 
		g = random.randrange(2, p-1)
		x = random.randrange(2, p-2)
		y = pow(g, x, p)

		self.public_key = (y, g, p)
		self.private_key = (x, p)
	
	def readKey(self, key:str, type:str) -> None:
		"""
		Read key from text input.
		"""
		try:
			# Modify the key based on file extension.
			if (type == "pub"):
				self.public_key = (int(key.split(" ")[0]), int(key.split(" ")[1]), int(key.split(" ")[2]))
			else:
				self.private_key = (int(key.split(" ")[0]), int(key.split(" ")[1]))
		except :
			raise Exception("INvalid key format")

	def loadKey(self, filename:str) -> None:
		"""
		Load key from .pri and .pub file.
		"""
		try:
			# Read the file.
			f = open(filename, "r")
			res = f.read()

			# Modify the key based on file extension.
			if (os.path.splitext(filename)[1].lower() == ".pub"):
				self.public_key = (int(res.split(" ")[0]), int(res.split(" ")[1]), int(res.split(" ")[2]))
			elif (os.path.splitext(filename)[1].lower() == ".pri"):
				self.private_key = (int(res.split(" ")[0]), int(res.split(" ")[1]))
			else :
				raise Exception("Invalid filename extension")
			
		except :
			raise Exception("Failed when opening file")

	def saveKey(self, is_public: bool = True, filename:str= str(datetime.now())) -> None:
		"""
		Write key to file .pri and .pub .
		"""
		# Filling filename and content.
		# Default case.
		ext = ".pub"
		content = str(self.public_key[0]) + " " + str(self.public_key[1]) + " " + str(self.public_key[2]) 
		
		# Private case.
		if (not is_public):
			ext = ".pri"
			content = str(self.private_key[0]) + " " + str(self.private_key[1])
		
		# Writing file to directory.
		filename += ext
		
		try:
			f = open(filename, "w")
			f.write(content)
		except :
			raise Exception("Failed when writing file")

class ElGamal_Crypt():
	def encrypt(self, plain_text: str, public_key:Tuple[int, int, int]) -> Tuple[str,str]:
		"""
		Encrypt the plaintext using elgamal algorithm. Public key can be generated using ElGamalKeygen
		class. Return tuple containing two ciphertext.
		"""
		# Get the public key.
		y, g, p = public_key

		# Prepare for encrypting.
		max_length = (len(str(p))-1)//3
		messages_int = plaintextToArrInt(plain_text, max_length)
		print("The block is:")
		print(messages_int)
    
		# Encrypt using elgamal algorithm.
		complete_a =[]
		complete_b =[]
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
	
	def decrypt(self, cipher_text: Tuple[str, str], private_key:Tuple[int, int]) -> str:
		"""
		Decrypt the ciphertext using elgamal algorithm. Private key can be generated using ElGamalKeygen
		class. Ciphertext must be a tuple of two string (a and b). Return plaintext.
		"""
		# Get the private key.
		x, p  = private_key
		
		# Prepare for decrypting.
		max_length = len(str(p))
		num_alphabet = (len(str(p))-1)//3
		list_a = cipher_text[0]
		list_int_a = ciphertextToArrInt(list_a, max_length)
		list_b = cipher_text[1]
		list_int_b = ciphertextToArrInt(list_b, max_length)
		
		# Decrypting using elgamal algorithm.
		list_ascii_plaintext = []
		for a, b in zip(list_int_a, list_int_b):
			first_equation = pow(a, p - 1 - x, p)
			plaintext_int = (b * first_equation) % p
			list_ascii_plaintext.append(str(plaintext_int).rjust(num_alphabet*3, "0"))

		# Parse list ascii plaintext to real plaintext.
		plaintext = ArrStrToPlaintext(list_ascii_plaintext, num_alphabet)
		return plaintext
		
		
# Test keygen.
def testKey():
	# Test loadfile.
	test = ElGamalKeygen()
	test.loadKey("yamet.pub")
	print("Loading pub")
	print("Public: ", end="")
	print(test.public_key)
	print("Private: ", end="")
	print(test.private_key)
	test.loadKey("yamet.pri")
	print("Loading pri")
	print("Public: ", end="")
	print(test.public_key)
	print("Private: ", end="")
	print(test.private_key)

	# Test generate random key.
	test = ElGamalKeygen()
	test.generateKey(is_random=False, p=2357)
	print("Random key")
	print("Public: ", end="")
	print(test.public_key)
	print("Private: ", end="")
	print(test.private_key)

def testElgamal():
	# Generate key.
	print("Generating key")
	key = ElGamalKeygen()
	key.generateKey(is_random=True, key_size=32)
	print("Public: ", end="")
	print(key.public_key)
	print("Private: ", end="")
	print(key.private_key)
	print()

	# Encrypt the message.
	print("Encrypting the plaintext")
	plaintext = "abcdefgh"
	print("The plaintext is ",  plaintext)
	elGamal = ElGamal_Crypt()
	ciphertext = elGamal.encrypt(plaintext, key.public_key)
	print("The ciphertext is")
	print("a: ", end="")
	print(ciphertext[0])
	print("b: ", end="")
	print(ciphertext[1])

	# Decrypt the message.
	print("Decrypting the ciphertext")
	a = '248557006365564747201258344916654576067065069181909619850746367712429893673504179763990760757009653728775395718917752144488138063562175954344661331540323522172665886630251486659297084416834666723245705493539698695477288323187743133220202483974122815837568190591408703129884029042150727334431425858513633122652596'
	b = '061492815646963708594421944683498300586108031012088853536455335210152859716975033476931081242409565795956353146901209213371731701200439810861651281314499062163888760577864377610116216572529816900199180107439683272788942695167840255378170757327280244299893259816225848516816082854502856743633874326149076543727844'
	plaintext = elGamal.decrypt((a,b), (93875277878827100014068644922214384135,253016361123993961339457386024926096871))
	print("The plaintext is ", plaintext)
	

# If module is being runned.
if __name__ == "__main__":
	# testKey()
	testElgamal()