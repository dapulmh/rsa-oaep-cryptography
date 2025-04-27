# cryptolib/oaep.py
"""
OAEP padding/unpadding utilities and MGF1 for RSA-OAEP.
- MGF1 based on SHA-256
- oaep_encode / oaep_decode for single-block operations
"""
import os
import math
import hashlib

from number_theory import modinv  # to avoid circular imports, if needed elsewhere


def mgf1(seed: bytes, mask_len: int) -> bytes:
    """
    Mask Generation Function based on SHA-256 (PKCS#1 MGF1).
    :param seed: input byte string
    :param mask_len: desired length of mask in bytes
    :return: mask of length mask_len
    """
    h = hashlib.sha256
    h_len = h().digest_size
    if mask_len > (1 << 32) * h_len:
        raise ValueError("mask too long")

    T = bytearray()
    K = math.ceil(mask_len / h_len)
    for counter in range(0, K):
        C = counter.to_bytes(4, byteorder='big')
        T.extend(h(seed + C).digest())
    return bytes(T[:mask_len])


def oaep_encode(message: bytes, k: int, k0: int = None, k1: int = None) -> bytes:
    """
    OAEP-encode a single block of message to length k bytes.
    Following PKCS#1 v2.1 OAEP padding format.
    """
    h_len = hashlib.sha256().digest_size  # 32 bytes
    if k0 is None:
        k0 = h_len
    if k1 is None:
        k1 = h_len

    # Calculate max message length
    max_msg_len = k - 2 * h_len - 2  # -2 for leading 0x00 byte and 0x01 separator
    if len(message) > max_msg_len:
        raise ValueError(f"Message too long: max {max_msg_len} bytes for this block, got {len(message)}")

    # Calculate DB length (must be exactly k - k0 - 1)
    db_len = k - k0 - 1
    
    # Calculate padding length
    ps_len = db_len - len(message) - 1
    
    # Create the data block with proper padding:
    # DB = PS || 0x01 || message
    # Where PS is a string of zeros
    db = bytearray(ps_len) + b'\x01' + message
    
    # Random seed
    r = os.urandom(k0)

    # Generate the DB mask
    db_mask = mgf1(r, db_len)
    
    # Debug checks
    if len(db) != len(db_mask):
        raise ValueError(f"Length mismatch: db={len(db)}, db_mask={len(db_mask)}")
    
    # Mask DB
    masked_db = bytes(db[i] ^ db_mask[i] for i in range(len(db)))

    # Mask seed
    seed_mask = mgf1(masked_db, k0)
    masked_seed = bytes(r[i] ^ seed_mask[i] for i in range(k0))

    # Final encoding: 0x00 || maskedSeed || maskedDB
    return b'\x00' + masked_seed + masked_db

def oaep_decode(encoded: bytes, k: int, k0: int = None, k1: int = None) -> bytes:
    """
    OAEP-decode a single block, returning the original message.
    Following PKCS#1 v2.1 OAEP padding format.
    """
    h_len = hashlib.sha256().digest_size
    if k0 is None:
        k0 = h_len
    if k1 is None:
        k1 = h_len

    if len(encoded) != k:
        raise ValueError(f"Encoded block must be exactly {k} bytes, got {len(encoded)}")

    # Leading byte must be 0x00
    if encoded[0] != 0x00:
        raise ValueError("Decoding error: first byte must be 0x00")
    
    # Split the encoded message
    masked_seed = encoded[1:k0+1]
    masked_db = encoded[k0+1:]

    # Recover the seed
    seed_mask = mgf1(masked_db, k0)
    seed = bytes(masked_seed[i] ^ seed_mask[i] for i in range(k0))

    # Recover the data block
    db_mask = mgf1(seed, len(masked_db))
    db = bytes(masked_db[i] ^ db_mask[i] for i in range(len(masked_db)))

    # Parse the data block
    # The format is: PS || 0x01 || message
    # Where PS is a string of zeros
    
    # Skip leading zeros (PS)
    i = 0
    while i < len(db) and db[i] == 0:
        i += 1
    
    # Next byte should be 0x01
    if i >= len(db) or db[i] != 0x01:
        raise ValueError("Invalid padding: no 0x01 separator found after PS")
    
    # The message is everything after the 0x01 separator
    return db[i+1:]

# if __name__ == '__main__':
#     import hashlib
#     h_len = hashlib.sha256().digest_size
#     k0 = h_len
#     k1 = h_len
#     k = 128  # 1024-bit modulus length in bytes
#     max_msg_len = k - k0 - k1 - 1
#     msg = b'A' * max_msg_len
#     print(f"Self-test: using msg length = {len(msg)} (block size = {max_msg_len}) bytes")
#     enc = oaep_encode(msg, k, k0=k0, k1=k1)
#     dec = oaep_decode(enc, k, k0=k0, k1=k1)
#     print(enc)
#     print(dec)
#     assert dec == msg, "Decoded message does not match original"
#     print("OAEP encode/decode self-test passed")
