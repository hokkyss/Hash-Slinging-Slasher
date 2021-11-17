from utils.RSA import RSA
from SHA256 import SHA256
from utils.message import bit_list_to_hex, string_to_bit_list

SIGN_PART = '***************SIGNED***************'

def verify(content: str, n: int, e: int, d: int) -> bool:
    last_message = content.find(SIGN_PART)
    last_sign = content.find(SIGN_PART, last_message + len(SIGN_PART))
    message = content[:last_message]
    signature = content[last_message + len(SIGN_PART):last_sign]

    message_digest = SHA256(message).hash()
    decrypted_sign = RSA(n, e, d).decrypt(signature)

    return message_digest == decrypted_sign

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
