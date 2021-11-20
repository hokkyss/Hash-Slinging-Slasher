from typing_extensions import Literal
from .RSA import *
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
def generateKey() -> List[str]:
    all_keys = None
    id = random.randint(0, 10000)

    all_keys = RSA.generate_key()

    public_key = ','.join(list(map(str, all_keys[0])))
    private_key = ','.join(list(map(str, all_keys[1])))

    return [public_key, private_key, f'RSA-{id}']

def proceed(public_key, private_key, mode: Literal['Sign', 'Verify'], message: str):
    if not mode:
        raise ValueError('You must either encrypt or decrypt')
    if not message:
        raise ValueError('Input a message.')

    if (mode == "Verify"):
        if not public_key:
            raise ValueError('Public key must not be empty!')

        public_key_arr = clean(public_key)
            
        if len(public_key_arr) != 2:
            raise ValueError('Public key format: <e>, <n>')
            
        e, n = public_key_arr[0], public_key_arr[1]
        return RSA(n, e, -1).encrypt(message)

    if (mode == "Sign"):
        if not private_key:
            raise ValueError('Private key must not be empty')
        private_key_arr = clean(private_key)

        if len(private_key_arr) != 2:
            raise ValueError('Private key format: <d>, <n>')    

        d, n = private_key_arr[0], private_key_arr[1]
        return RSA(n, -1, d).decrypt(message)
