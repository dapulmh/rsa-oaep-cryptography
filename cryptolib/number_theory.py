"""
Number-theoretic utilities for RSA-OAEP:
- Miller–Rabin primality test
- Random prime generation
- Extended Euclidean algorithm
- Modular inverse
"""
import random
import math

def is_prime(n: int, k: int = 40) -> bool:
    """
    Miller–Rabin probabilistic primality test.
    :param n: the integer to test for primality
    :param k: number of testing rounds (higher = more accuracy)
    :return: True if n is probably prime, False if composite
    """
    if n < 2:
        return False
    # small primes
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False
    # write n - 1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    # witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """
    Generate a prime number of specified bit length.
    :param bits: number of bits for the prime
    :return: a probable prime integer of 'bits' bits
    """
    assert bits >= 2, "Bit length must be at least 2"
    while True:
        # ensure MSB = 1 to get full bit length, and LSB = 1 to ensure odd
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(candidate):
            return candidate


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.
    :param a: first integer
    :param b: second integer
    :return: (g, x, y) such that g = gcd(a, b) and a*x + b*y = g
    """
    if b == 0:
        return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def modinv(a: int, m: int) -> int:
    """
    Compute modular inverse of a modulo m, i.e. find x such that a*x ≡ 1 (mod m).
    :param a: integer whose inverse is sought
    :param m: modulus
    :return: modular inverse x
    :raises ValueError: if inverse does not exist (i.e. a and m are not coprime)
    """
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist for a={a}, m={m}")
    return x % m

# Quick CLI tests
# if __name__ == '__main__':
#     # sanity-check prime gen
#     p = generate_prime(16)
#     q = generate_prime(16)
#     print(f"Generated 16-bit primes p={p}, q={q}")
#     # check modinv correctness
#     for a in [3, 17, 23]:
#         inv = modinv(a, 40)
#         assert (a * inv) % 40 == 1
#     print("modinv tests passed")