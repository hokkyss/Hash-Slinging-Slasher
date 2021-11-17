from typing_extensions import Literal
from .RSA import *
from .ElGamal import *
from .Paillier import *
from .EllipticCurve import *
from .utils import *

# Read the file and return the content of the file
def readFile(filename: str) -> str:
    f = open("keys/" + filename, "r")
    output_text = f.read()
    return output_text

# Clean the key into list of value contain in key
def clean(text: str) -> List[int]:
    clean_text = text.replace(" ", "")
    int_arr = list(map(int, clean_text.split(",")))
    return int_arr

# Generate the key based on user choice
def generateKey(choice: Literal['RSA', 'ElGamal', 'Paillier', 'ECC']) -> List[str]:
    if not choice:
        raise ValueError('You must choose a Cryptography Algorithm.')
    all_keys = None
    filename = ""
    id = random.randint(0, 1000)

    if (choice == "RSA"):
        all_keys = generate_rsa_key()
        filename = "rsa-" + str(id)
    elif (choice == "ElGamal"):
        all_keys = ElGamal.generate_key()
        filename = "elgamal-" + str(id)
    elif (choice == "Paillier"):
        all_keys = generate_paillier_key()
        filename = "paillier-" + str(id)
    elif (choice == "Elliptic Curve Cryptography"):
        all_keys = EllipticCurve.generate_key()
        filename = "ecc-" + str(id)

    public_key = ','.join(list(map(str, all_keys[0])))
    private_key = ','.join(list(map(str, all_keys[1])))

    return [public_key, private_key, filename]


def proceed(public_key, private_key, choice: Literal['RSA', 'ElGamal', 'Paillier', 'Elliptic Curve Cryptography'], mode: Literal['Encryption', 'Decryption'], message: str):
    if not choice:
        raise ValueError('You must choose a Cryptography Algorithm.')
    if not mode:
        raise ValueError('You must either encrypt or decrypt')
    if not message:
        raise ValueError('Input a message.')

    if (mode == "Encryption"):
        if not public_key:
            raise ValueError('Public key must not be empty!')
        if (choice == "RSA"):
            public_key_arr = clean(public_key)
            
            if len(public_key_arr) != 2:
                raise ValueError('Public key format: <e>, <n>')
            
            e, n = public_key_arr[0], public_key_arr[1]
            return rsa_encryption(message, n, e)

        if (choice == "Paillier"):
            public_key_arr = clean(public_key)

            if len(public_key_arr) != 2:
                raise ValueError('Public key format: <g>, <n>')
            m: int = int(message)

            g, n = public_key_arr[0], public_key_arr[1]
            if ((m > n) or (m < 0)):
                raise ValueError('Message must be between 0 and n')
            return paillier_encryption(m, g, n)
        if (choice == "ElGamal"):
            public_key_arr = clean(public_key)

            if len(public_key_arr) != 3:
                raise ValueError('Public key format: <p>, <g>, <y>')
            [p, g, y] = public_key_arr

            (message_block, digit) = message_blocking(p, message, p)

            result = ElGamal.encrypt(message_block, (p, g, y))
            string_array: List[str] = []
            for (g_k, y_k_block) in result:
                string_array.append(str(g_k).zfill(digit) + str(y_k_block).zfill(digit))
            return "".join(string_array)
        if (choice == "Elliptic Curve Cryptography"):
            public_key_arr = clean(public_key)

            if len(public_key_arr) != 4:
                raise ValueError('Public key format: <B.x>, <B.y>, <Pb.x>, <Pb.y>')
            [Bx, By, PbX, PbY] = public_key_arr
            EllipticCurve.check_validity(Bx, By, PbX, PbY)

            B = EllipticCurve(Bx, By)
            mess = EllipticCurve.encode(message)

            return B.encrypt(mess, (PbX, PbY))
    if (mode == "Decryption"):
        if not private_key:
            raise ValueError('Private key must not be empty')
        if (choice == "RSA"):
            private_key_arr = clean(private_key)

            if len(private_key_arr) != 2:
                raise ValueError('Private key format: <d>, <n>')    

            d, n = private_key_arr[0], private_key_arr[1]
            return rsa_decryption(message, n, d)
        if (choice == "Paillier"):
            private_key_arr = clean(private_key)

            if len(private_key_arr) != 3:
                raise ValueError('Private key format: <λ>, <µ>, <n>')

            lamda, miu, n = private_key_arr[0], private_key_arr[1], private_key_arr[2]
            m: int = int(message)
            if ((m > n * n) or (m < 0)):
                raise ValueError('Ciphertext must be between 0 and n^2')
            return paillier_decryption(int(message), lamda, miu, n)
        if (choice == "ElGamal"):
            private_key_arr = clean(private_key)
            
            if len(private_key_arr) != 2:
                raise ValueError('Private key format: <p>, <x>')

            [p, x] = private_key_arr

            (message_block, digits) = message_blocking(p, message, p)

            parsed_message: List[Tuple[int, int]] = []
            for i in range(0, len(message_block), 2):
                parsed_message.append((message_block[i], message_block[i + 1]))
            
            decrypted = ElGamal.decrypt(parsed_message, (p, x))

            return "".join(list(map(str, decrypted)))
        if (choice == "Elliptic Curve Cryptography"):
            private_key_arr = clean(private_key)

            if len(private_key_arr) != 3:
                raise ValueError('Private key format: <b>, <B.x>, <B.y>')
            [b, x, y] = private_key_arr
            EllipticCurve.check_validity(x, y)

            B = EllipticCurve(x, y)

            if len(clean(message)) % 4 != 0:
                raise ValueError('Number of integers must be dividable by 4!')

            mess: List[int] = clean(message)
            parsed_message: List[Tuple[Tuple[int, int], Tuple[int, int]]] = []
            for i in range(0, len(mess), 4):
                parsed_message.append(((mess[i], mess[i + 1]), (mess[i + 2], mess[i + 3])))

            return B.decrypt(parsed_message, b)
