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
    for counter in range(0, math.ceil(mask_len / h_len)):
        C = counter.to_bytes(4, byteorder='big')
        T.extend(h(seed + C).digest())
    return bytes(T[:mask_len])


def oaep_encode(message: bytes, k: int, k0: int = None, k1: int = None) -> bytes:
    """
    OAEP-encode a single block of message to length k bytes (== modulus length in bytes).
    :param message: input data bytes (length <= k - k0 - k1)
    :param k: modulus length in bytes
    :param k0: length of random seed in bytes (defaults to hash length)
    :param k1: length of zero padding in bytes (defaults to hash length)
    :return: encoded block of length k bytes
    """
    h_len = hashlib.sha256().digest_size
    if k0 is None:
        k0 = h_len
    if k1 is None:
        k1 = h_len

    max_msg_len = k - k0 - k1 - 1
    if len(message) > max_msg_len:
        raise ValueError(f"Message too long: max {max_msg_len} bytes for this block")

    # Data block: m || zeroes
    db = message + b"\x00" * k1

    # Random seed r
    r = os.urandom(k0)

    # Compute maskedDB and maskedSeed
    db_mask = mgf1(r, k - k0-1)
    masked_db = bytes(db[i] ^ db_mask[i] for i in range(len(db_mask)))

    seed_mask = mgf1(masked_db, k0)
    masked_seed = bytes(r[i] ^ seed_mask[i] for i in range(k0))

    # Output: maskedSeed || maskedDB
    return b'\x00' + masked_seed + masked_db


def oaep_decode(encoded: bytes, k: int, k0: int = None, k1: int = None) -> bytes:
    """
    OAEP-decode a single block, returning the original message.
    :param encoded: encoded block of length k bytes
    :param k: modulus length in bytes
    :param k0: length of random seed (defaults to hash length)
    :param k1: length of zero padding (defaults to hash length)
    :return: original message bytes
    :raises ValueError: if padding is invalid
    """
    h_len = hashlib.sha256().digest_size
    if k0 is None:
        k0 = h_len
    if k1 is None:
        k1 = h_len

    if len(encoded) != k:
        raise ValueError(f"Encoded block must be exactly {k} bytes")

    # Check and strip leading 0x00 byte
    if encoded[0] != 0x00:
        raise ValueError("Decoding error: expected leading 0x00 byte")
    masked_seed = encoded[1:k0+1]
    masked_db = encoded[k0+1:]

    seed_mask = mgf1(masked_db, k0)
    r = bytes(masked_seed[i] ^ seed_mask[i] for i in range(k0))

    db_mask = mgf1(r, k - k0 - 1)
    db = bytes(masked_db[i] ^ db_mask[i] for i in range(len(db_mask)))

    m, zero_pad = db[:len(db) - k1], db[len(db) - k1:]
    if any(zero_pad):
        raise ValueError("OAEP decode error: zero-padding check failed")

    return m

if __name__ == '__main__':
    import hashlib
    h_len = hashlib.sha256().digest_size
    k0 = h_len
    k1 = h_len
    k = 128  # 1024-bit modulus length in bytes
    max_msg_len = k - k0 - k1 - 1
    msg = b'A' * max_msg_len
    print(f"Self-test: using msg length = {len(msg)} (block size = {max_msg_len}) bytes")
    enc = oaep_encode(msg, k, k0=k0, k1=k1)
    dec = oaep_decode(enc, k, k0=k0, k1=k1)
    print(enc)
    print(dec)
    assert dec == msg, "Decoded message does not match original"
    print("OAEP encode/decode self-test passed")
