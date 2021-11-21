from typing_extensions import Literal
from utils.verify import verify
from utils.SHA256 import SHA256
from .RSA import *
from .utils import *

SIGN_PART = '***************SIGNED***************'

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

def proceed(public_key, private_key, mode: Literal['Sign', 'Verify'], content: str) -> str:
    if not mode:
        raise ValueError('You must either sign or verify a *.txt file')
    if not content:
        raise ValueError('Input a message or upload a *.txt file.')

    if (mode == "Verify"):
        if not public_key:
            raise ValueError('Public key must not be empty!')

        public_key_arr = clean(public_key)
            
        if len(public_key_arr) != 2:
            raise ValueError('Public key format: <e>, <n>')
            
        e, n = public_key_arr[0], public_key_arr[1]
        return verify(content, n, e, -1)

    if (mode == "Sign"):
        if not private_key:
            raise ValueError('Private key must not be empty')
        private_key_arr = clean(private_key)

        if len(private_key_arr) != 2:
            raise ValueError('Private key format: <d>, <n>')

        message = SHA256(content).hash()

        d, n = private_key_arr[0], private_key_arr[1]
        return f'{SIGN_PART}{RSA(n, -1, d).encrypt(message)}{SIGN_PART}'
