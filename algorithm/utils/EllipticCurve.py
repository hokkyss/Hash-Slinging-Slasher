from typing import ClassVar, Dict, List, Tuple
from random import choice, randint, shuffle
from string import ascii_uppercase, ascii_lowercase, digits

from .utils import PrimeGenerator, StringEncoder, inverse_modulo, pow_mod

class EllipticCurve:
    __INFINITY: ClassVar[Tuple[int, int]] = (0, 10000000000000000000000000000000000000000000000000000000000000000)
    __k: ClassVar[int] = 2957
    __a: ClassVar[int] = 2969
    __b: ClassVar[int] = 2971
    __p: ClassVar[int] = 2999
    __table: ClassVar[List[int]] = []
    __encoding_table: ClassVar[Dict[str, Tuple[int, int]]] = {}
    __decoding_table: ClassVar[Dict[str, str]] = {}
    __ALL_POINTS: ClassVar[List[Tuple[int, int]]] = []

    def __init__(self, x: int, y: int) -> None:
        self.x = x
        self.y = y
        p = EllipticCurve.__p

    def multiply(self, k: int):
        if k < 0:
            negative = self.multiply(-k)
            return EllipticCurve(negative.x, -negative.y)
        if k == 0:
            (xO, yO) = EllipticCurve.__INFINITY
            return EllipticCurve(xO, yO)
        if k == 1:
            return self

        multiplier = k // 2
        remainder = k % 2

        temp = self.multiply(multiplier)

        return temp.add(temp).add(self.multiply(remainder))

    def add(self, other):
        (xP, yP) = self.x, self.y

        xQ: int; yQ: int
        (xQ, yQ) = other.x, other.y
        (xO, yO) = EllipticCurve.__INFINITY

        p = EllipticCurve.__p

        if yP == yO:
            return other
        if yQ == yO:
            return self
        if (xP == xQ) and (yP == -yQ):
            return EllipticCurve(xO, yO)
        if (xP == xQ) and (yP == yQ):
            m = inverse_modulo(2 * yP, p) * (3 * pow_mod(xP, 2, p) + EllipticCurve.__a) % p

            xR = (pow_mod(m, 2, p) - (2 * xP)) % p
            yR = (m * (xP - xR) - yP) % p
            return EllipticCurve(xR, yR)

        m = (((yP - yQ) % p) * inverse_modulo((xP - xQ) % p, p)) % p

        xR = (pow_mod(m, 2, p) - xP - xQ) % p
        yR = (((m * (xP - xR)) % p) - yP) % p

        return EllipticCurve(xR, yR)

    def subtract(self, other):
        return self.add(other.multiply(-1))

    def __str__(self) -> str:
        return f"{self.x},{self.y}"

    def encrypt(self, m: List[Tuple[int, int]], public_key: Tuple[str, str]):
        """
        - `m` list of ECCPoints
        - `p` is any prime number
        - `public_key` is Pb
        - `param` is (a, b) of the used elliptic curve for encoding
        """
        result: List[Tuple[str, str]] = []
        (xpub, ypub) = public_key
        public = EllipticCurve(xpub, ypub)

        for Pm in m:
            (x, y) = Pm
            k = randint(1, EllipticCurve.__p - 1)

            Pc = (str(self.multiply(k)), str(EllipticCurve(x, y).add(public.multiply(k))))
            result.append(Pc)
        return result

    @staticmethod
    def check_validity(Bx: int, By: int):
        p = EllipticCurve.__p
        if (Bx >= 0 and Bx < p and By >= 0 and By < p):
            pass
        else:
            raise ValueError(f'Each number must be between {0} and {p - 1}, inclusively!')

    @staticmethod
    def check_validity(Bx: int, By: int, PbX: int, PbY: int):
        p = EllipticCurve.__p
        if Bx >= 0 and Bx < p and By >= 0 and By < p and PbX >= 0 and PbX < p and PbY >= 0 and PbY < p:
            pass
        else:
            raise ValueError(f'Each number must be between {0} and {p - 1}, inclusively!')

    @staticmethod
    def decrypt(m: List[Tuple[Tuple[int, int], Tuple[int, int]]], private_key: int) -> List[int]:
        result: List[str] = []
        p = EllipticCurve.__p

        for (a, b) in m:
            (xa, ya) = a
            (xb, yb) = b

            if (xa < 0) or (xa >= p) or (ya < 0) or (ya >= p) or (xb < 0) or (xb >= p) or (yb < 0) or (yb >= p):
                raise ValueError(f'Each number must be between {0} and {p - 1}, inclusively!')

            subtractor = EllipticCurve(xa, ya).multiply(private_key)
            Pm = EllipticCurve(xb, yb).subtract(subtractor)

            result.append(EllipticCurve.__decode(str(Pm)))
        return "".join(result)

    @staticmethod
    def encode(m: str) -> List[Tuple[int, int]]:
        result: List[Tuple[int, int]] = []
        table = EllipticCurve.__table
        k = EllipticCurve.__k
        p = EllipticCurve.__p
        taken: List[List[bool]] = [[False for _ in range(p)] for __ in range(p)]

        encoding_table = EllipticCurve.__encoding_table
        decoding_table = EllipticCurve.__decoding_table
        for c in m:
            try:
                result.append(encoding_table[c])
            except:
                in_int = StringEncoder.encode(c)
                p = EllipticCurve.__p
                a = EllipticCurve.__a
                b = EllipticCurve.__b

                y: int = None
                for x in range(in_int * k + 1, in_int * k + 1 + p):
                    x = x % p
                    kuadrat = (pow_mod(x, 3, p) + x * a + b) % p
                    for i in range(p):
                        if taken[x][i]:
                            continue
                        if table[i] == kuadrat:
                            y = i
                            break

                    if y != None:
                        taken[x][y] = True
                        encoding_table[c] = (x, y)
                        decoding_table[str(EllipticCurve(x, y))] = c
                        break
                if not y:
                    (x, y) = EllipticCurve.__INFINITY
                result.append((x, y))

        return result

    @staticmethod
    def __get_y(x: int) -> List[int]:
        p = EllipticCurve.__p
        a = EllipticCurve.__a
        b = EllipticCurve.__b

        x = x % p
        kuadrat = (pow_mod(x, 3, p) + x * a + b) % p
        result: List[int] = []
        for i in range(p):
            if EllipticCurve.__table[i] == kuadrat:
                result.append(i)
        return result

    @staticmethod
    def generate():
        if len(EllipticCurve.__encoding_table.keys()) != 0: return

        p = EllipticCurve.__p
        table = EllipticCurve.__table

        for i in range(p):
            table.append(pow_mod(i, 2, p))

        all_characters = list(ascii_lowercase + ascii_uppercase + digits + " ")
        shuffle(all_characters)

        EllipticCurve.encode(all_characters)

        for i in range(p):
            points: List[Tuple[int, int]] = EllipticCurve.__get_y(i)

            for y in points:
                EllipticCurve.__ALL_POINTS.append((i, y))

    @staticmethod
    def __decode(string: str) -> str:
        return EllipticCurve.__decoding_table[string]

    @staticmethod
    def generate_key():
        base = choice(EllipticCurve.__ALL_POINTS)

        private = PrimeGenerator.random_below(EllipticCurve.__p - 1)
        (x, y) = base
        B = EllipticCurve(x, y)
        pB = B.multiply(private)

        return [[str(B), str(pB)], [private, str(B)]]
