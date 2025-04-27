# cryptolib/file_util.py
def read_key_from_file(filename: str) -> tuple:
    """
    Read a key from a file.
    
    :param filename: Path to the key file
    :return: Tuple (exponent, modulus)
    """
    with open(filename, 'r') as f:
        key_str = f.read().strip()
        parts = key_str.split(',')
        if len(parts) != 2:
            raise ValueError("Invalid key format")
        return (int(parts[0], 16), int(parts[1], 16))
    

# Save the key to a file in hexadecimal format
def save_key_to_file(key: tuple, filename: str):
    with open(filename, 'w') as f:
        hex_key = f"{key[0]:x},{key[1]:x}"  # Convert both e/n or d/n to hexadecimal format
        f.write(hex_key)