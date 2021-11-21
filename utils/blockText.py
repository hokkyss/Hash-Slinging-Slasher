from typing import Tuple, List


def plaintextToArrInt(plaintext:str, max_length:int) -> List[int]:
    """
    Convert plaintext to array of integer for encrypt.
    """
    equalSizedStr = [plaintext[i:i+max_length] for i in range(0, len(plaintext), max_length)]
    block = []
    for string in equalSizedStr:
        ascii_string =""
        for char in string:
            ascii_string += str(ord(char)).rjust(3, "0")
        block.append(int(ascii_string))
    return block

def ciphertextToArrInt(ciphertext:str, max_length:int) -> List[int]:
    """
    Convert ciphertext to array of integer for decrypt.
    """
    equalSizedStr = [ciphertext[i:i+max_length] for i in range(0, len(ciphertext), max_length)]
    block = [int(ciphertext) for ciphertext in equalSizedStr]
    return block

def ArrStrToPlaintext(arr_str:List[str], num_alphabet:int)-> str:
    """
    Convert list of plaintext in ascii to string of normal plaintext.
    """
    plaintext = ""
    for combined_ascii in arr_str:
        temp = [combined_ascii[i:i+3] for i in range(0, len(combined_ascii), 3)]
        for ascii in temp:
            if (int(ascii)!= 0):
                plaintext += chr(int(ascii)) 
    return plaintext


def ciphertextToArrTupleInt(ciphertext:str, max_length:int) -> List[Tuple[int, int]]:
    """
    # Helper for ECEG algorithm.
    Convert ciphertext to array of tuple(int,int) for decrypt.
    """
    max_length_tuple = max_length*2
    equalSizedTuple = [ciphertext[i:i+max_length_tuple] for i in range(0, len(ciphertext), max_length_tuple)]
    equalSizedStr = [(tuple[0:max_length],tuple[max_length:max_length*2]) for tuple in equalSizedTuple]
    block = [(int(tuple[0]),int(tuple[1])) for tuple in equalSizedStr]
    
    return block


    