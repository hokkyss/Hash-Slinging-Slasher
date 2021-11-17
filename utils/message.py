from typing import List, Union
from typing_extensions import Literal

def string_to_bit_list(message: str) -> List[Literal[0, 1]]:
    byte_message_list = [bin(ord(chr))[2:].zfill(8) for chr in message]
    bytes_message_string = ''.join(byte_message_list)
    bit_message_list = [int(bit) for bit in list(bytes_message_string)]

    return bit_message_list

def bit_list_to_hex(bit_message_list: List[Literal[0, 1]]) -> str:
    bytes_message_string = ''.join([str(bit) for bit in bit_message_list])
    message_value_chunk_4 = [
        int('0b' + bytes_message_string[i: i + 4], 2) for i in range(0, len(bytes_message_string), 4)
    ]
    hex_message = ''.join([hex(val)[2:] for val in message_value_chunk_4])

    return hex_message


def pad_with_zero(bits: List[Literal[0, 1]], expected_length: int, pad_from: Literal['right', 'left']):
    bits_length = len(bits)
    total_loop = abs(expected_length - bits_length)

    if(pad_from == 'left'):
        for _ in range(total_loop):
            bits.insert(0, 0)

    elif(pad_from == 'right'):
        for _ in range(total_loop):
            bits.append(0)

    return bits


def chunk_bits(bits: List[Union[str, int]], expected_chunk_length: int):
    return [bits[i: i + expected_chunk_length] for i in range(0, len(bits), expected_chunk_length)]
