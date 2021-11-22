from utils.ElGamal import ElGamal
from .RSA import RSA
from .SHA256 import SHA256
from .message import bit_list_to_hex, string_to_bit_list

SIGN_PART = '***************SIGNED***************'

def verify(content: str, p: int, x: int) -> str:
    last_message = content.find(SIGN_PART)
    last_sign = content.find(SIGN_PART, last_message + len(SIGN_PART))
    if last_message == -1 or last_sign == -1:
        raise ValueError('Sign format invalid!')

    message = content[:last_message]
    signature = content[last_message + len(SIGN_PART): last_sign]
    message_digest = SHA256(message).hash()

    signature = signature.replace(" ", "")
    [ciphertext_a, ciphertext_b] = signature.split(",")
    decrypted_sign = ElGamal.decrypt((ciphertext_a, ciphertext_b), (p, x))

    if message_digest != decrypted_sign:
        raise ValueError('Sign cannot be verified!')

    return message
