# RSA Key Generation
import random
import math
from number_theory import *
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

# Save the key to a file in hexadecimal format
def save_key_to_file(key: tuple, filename: str):
    with open(filename, 'w') as f:
        hex_key = f"{key[0]:x},{key[1]:x}"  # Convert both e/n or d/n to hexadecimal format
        f.write(hex_key)

# Generate RSA key pair (2048 bits)
public_key, private_key = rsa_key_generation(2048)

# Save the keys to files
save_key_to_file(public_key, 'public_key.txt')
save_key_to_file(private_key, 'private_key.txt')

print("RSA key pair generated and saved to files.")