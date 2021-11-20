import random
from textwrap import wrap
from typing import ClassVar, List, Tuple

class PrimeGenerator:
    __PRIMES: ClassVar[List[int]]

    @staticmethod
    def fill() -> None:
        PrimeGenerator.__PRIMES = []
        n = 10000000
        prime = [True] * n
        for i in range(3, int(n ** 0.5) + 1 , 2):
            if prime[i]:
                prime[i * i:: 2 * i] = [False]*((n - i * i - 1) // (2 * i) + 1)

        PrimeGenerator.__PRIMES = [2] + [i for i in range(3, n, 2) if prime[i]]
        ### SECURITY TO PREVENT PRIMES LOWER THAN 16 TO BE GENERATED (RSA)
        PrimeGenerator.__PRIMES.remove(2)
        PrimeGenerator.__PRIMES.remove(3)
        PrimeGenerator.__PRIMES.remove(5)
        PrimeGenerator.__PRIMES.remove(7)
        PrimeGenerator.__PRIMES.remove(11)
        PrimeGenerator.__PRIMES.remove(13)

    @staticmethod
    def random():
        return random.choice(PrimeGenerator.__PRIMES)
    
    @staticmethod
    def random_below(n):
        filtered_prime = [x for x in PrimeGenerator.__PRIMES if x <= n]
        selected_prime = random.choice(filtered_prime)
        while (gcd(selected_prime, n) != 1):
            selected_prime = random.choice(filtered_prime)
        return selected_prime

def pow_mod(x: int, y: int, p: int) -> int:
    """
    Count (x ** y) % p using divide and conquer.

    x > 0
    """
    assert x >= 0
    x = x % p

    if x == 0: return 0
    if y == 0: return 1
    if y == 1: return x

    temp: int = pow_mod(x, y // 2, p)
    return (temp * temp * pow_mod(x, y % 2, p)) % p

def gcd(a: int, b: int) -> int:
    if a == 0: return b
    return gcd(b % a, a)

def lcm(a: int, b: int) -> int:
    return (a * b) // gcd(a, b)

def inverse_modulo(a: int, m: int) -> int:
    """
    Count (1 / a) % m using bezout identity.
    @documentation https://www.dcode.fr/bezout-identity
    """
    assert gcd(a, m) == 1

    r = a; r_ = m
    u = 1; u_ = 0
    v = 0; v_ = 1
    while r_ != 0:
        q = r // r_
        r_temp = r;             u_temp = u;             v_temp = v
        r = r_;                 u = u_;                 v = v_
        r_ = r_temp - (q * r_); u_ = u_temp - (q * u_); v_ = v_temp - (q * v_)
    
    # if u is negative, u becomes positive.
    return u % m

def message_blocking(private: int, message: str, p: int) -> Tuple[List[int], int]:
    digits: int = len(str(private))
    messages: List[int]
    try:
        messages = list(map(int, wrap(message, digits)))
        for block in messages:
            if (block >= p) or (block < 0):
                raise ValueError
    except:
        messages = list(map(int, wrap(message, digits - 1)))
        return messages, digits - 1
    return messages, digits
