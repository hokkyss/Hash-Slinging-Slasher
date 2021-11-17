from typing import Tuple
from utils.message import bit_list_to_hex, string_to_bit_list

SIGN_PART = '***************SIGNED***************'

def decrypt(content: str, public_key: Tuple[int, int]):
    message = bit_list_to_hex(string_to_bit_list(content))
    (e, n) = public_key

def verify(content: str):
    last_message = content.find(SIGN_PART)
    last_sign = content.find(SIGN_PART, last_message + len(SIGN_PART))
    message = content[:last_message]
    signature = content[last_message + len(SIGN_PART):last_sign]

if __name__ == '__main__':
    content = "HALO TEMAN-TEMAN SEMUA\r\n\r\n***************SIGNED***************ABCDEF***************SIGNED***************"
    last_message = content.find(SIGN_PART)
    last_sign = content.find(SIGN_PART, last_message + len(SIGN_PART))
    message = content[:last_message]
    print(message)
    signature = content[last_message + len(SIGN_PART):last_sign]
    print(signature)
    message = bit_list_to_hex(string_to_bit_list(message))
    print(message)
