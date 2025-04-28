import random
import math
from number_theory import generate_prime, modinv

"""
Referensi :
    slide scele
"""
def rsa_key_generation(bits: int = 2048) -> tuple:
    # Generate two large primes
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    
    # Compute n = p * q
    n = p * q
    
    # Compute Euler's Totient φ(n) = (p-1)(q-1)
    phi_n = (p - 1) * (q - 1)
    
    # Choose e (commonly 65537)
    e = 65537
    
    # Compute d, the modular inverse of e mod φ(n)
    d = modinv(e, phi_n)
    
    # Public key: (e, n)
    # Private key: (d, n)
    return (e, n), (d, n)

