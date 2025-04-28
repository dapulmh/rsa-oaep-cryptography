import os
from oaep import oaep_encode, oaep_decode
from file_util import read_key_from_file



def encrypt_file(input_file, output_file, public_key_file):
    """
    Encrypt a file using RSA-OAEP.
    """
    # Read public key
    public_key = read_key_from_file(public_key_file)
    e, n = public_key
    
    # Calculate modulus length in bytes
    k = (n.bit_length() + 7) // 8
    
    # Calculate maximum message length per block
    h_len = 32  # SHA-256 output length in bytes
    max_msg_len = k - 2 * h_len - 2  # 2 bytes for 0x00 leading byte and 0x01 separator
    
    print(f"Modulus length: {k} bytes")
    print(f"Max message length per block: {max_msg_len} bytes")
    
    with open(input_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
        chunk_counter = 0
        while True:
            # Read a chunk no larger than max_msg_len
            chunk = in_file.read(max_msg_len)
            if not chunk:
                break
            
            chunk_counter += 1
            print(f"Processing chunk {chunk_counter}, size: {len(chunk)} bytes")
            
            # Pad the chunk using OAEP
            padded_chunk = oaep_encode(chunk, k)
            
            # Convert bytes to integer
            m = int.from_bytes(padded_chunk, byteorder='big')
            
            # # RSA encryption: c = m^e mod n
            c = pow(m, e, n)
            
            # Write the encrypted chunk
            ciphertext_bytes = c.to_bytes(k, byteorder='big')
            out_file.write(ciphertext_bytes)
        
        print(f"Encryption complete. Processed {chunk_counter} chunks.")

def decrypt_file(input_file: str, output_file: str, private_key_file: str):
    """
    Decrypt a file using RSA-OAEP.
    
    :param input_file: Path to the input file (ciphertext)
    :param output_file: Path to the output file (plaintext)
    :param private_key_file: Path to the private key file
    """
    private_key = read_key_from_file(private_key_file)
    d, n = private_key
    
    # Calculate modulus length in bytes
    k = (n.bit_length() + 7) // 8
    
    file_size = os.path.getsize(input_file)
    if file_size % k != 0:
        raise ValueError(f"Invalid ciphertext file size. Expected multiple of {k} bytes.")
    
    total_chunks = file_size // k
    
    with open(input_file, 'rb') as in_file, open(output_file, 'wb') as out_file:
        chunk_counter = 0
        while True:
            # Read a block of k bytes
            ciphertext_bytes = in_file.read(k)
            if not ciphertext_bytes:
                break
            
            chunk_counter += 1
            print(f"Processing chunk {chunk_counter}, size: {len(ciphertext_bytes)} bytes")
            
            # Convert bytes to integer
            c = int.from_bytes(ciphertext_bytes, byteorder='big')

            # # RSA decryption: m = c^d mod n
            m = pow(c, d, n)
            
            # Convert to bytes and unpad using OAEP
            padded_bytes_len = k
            padded_chunk = m.to_bytes(padded_bytes_len, byteorder='big')
            
            try:
                chunk = oaep_decode(padded_chunk, k)
                # Write the decrypted chunk to the output file
                out_file.write(chunk)
            except ValueError as e:
                print(f"Error decoding chunk {chunk_counter}: {e}")
                raise e
    
    print(f"Decryption complete. Processed {chunk_counter} chunks.")
