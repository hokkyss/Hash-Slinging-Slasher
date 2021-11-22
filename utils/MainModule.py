from typing_extensions import Literal

from utils.ElGamal import ElGamal
from utils.verify import verify
from utils.SHA256 import SHA256
from .utils import *

SIGN_PART = '***************SIGNED***************'

# Clean the key into list of value contain in key
def clean(text: str) -> List[int]:
    clean_text = text.replace(" ", "")
    int_arr = list(map(int, clean_text.split(",")))
    return int_arr

# Generate the key based on user choice
def generateKey() -> List[str]:
    all_keys = None
    id = random.randint(0, 10000)

    all_keys = ElGamal.generate()

    public_key = ','.join(list(map(str, all_keys[0])))
    private_key = ','.join(list(map(str, all_keys[1])))

    return [public_key, private_key, f'ElGamal-{id}']

def proceed(public_key, private_key, mode: Literal['Sign', 'Verify'], content: str) -> str:
    if not mode:
        raise ValueError('You must either sign or verify a *.txt file')
    if not content:
        raise ValueError('Input a message or upload a *.txt file.')

    if (mode == "Verify"):
        if not private_key:
            raise ValueError('Private key must not be empty!')

        private_key_arr = clean(private_key)
            
        if len(private_key_arr) != 2:
            raise ValueError('Public key format: <p>, <x>')
            
        p, x = private_key_arr
        return verify(content, p, x)

    if (mode == "Sign"):
        if not public_key:
            raise ValueError('Public must not be empty')
        public_key_arr = clean(public_key)

        if len(public_key_arr) != 3:
            raise ValueError('Private key format: <p>, <g>, <y>')

        message = SHA256(content).hash()

        p, g, y = public_key_arr
        encrypted = ElGamal.encrypt(message, (p, g, y))
        return f'{SIGN_PART}{encrypted[0]},{encrypted[1]}{SIGN_PART}'
