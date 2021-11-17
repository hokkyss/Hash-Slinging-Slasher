from typing import List
from typing_extensions import Literal

def isTrue(x: Literal[0, 1]): return x == 1

def if_(i: Literal[0, 1], y, z): return y if isTrue(i) else z

def and_(i: Literal[0, 1], j: Literal[0, 1]): return if_(i, j, 0)
def AND(i: List[Literal[0, 1]], j: List[Literal[0, 1]]): return [and_(ia, ja) for ia, ja in zip(i, j)]

def not_(i: Literal[0, 1]): return if_(i, 0, 1)
def NOT(i: List[Literal[0, 1]]): return [not_(x) for x in i]


def xor(i, j): return if_(i, not_(j), j)
def XOR(i, j): return [xor(ia, ja) for ia, ja in zip(i, j)]


def xorxor(i, j, l): return xor(i, xor(j, l))
def XORXOR(i, j, l): return [xorxor(ia, ja, la)
                             for ia, ja, la, in zip(i, j, l)]


def maj(i, j, k): return max([i, j, ], key=[i, j, k].count)


def rotr(x, n): return x[-n:] + x[:-n]


def shr(x, n): return n * [0] + x[:-n]


def add(i, j):
    length = len(i)
    sums = list(range(length))
    c = 0
    for x in range(length-1, -1, -1):
        sums[x] = xorxor(i[x], j[x], c)
        c = maj(i[x], j[x], c)
    return sums
