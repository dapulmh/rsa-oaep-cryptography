from rsa_key_generator import rsa_key_generation
from file_util import save_key_to_file
from rsa import encrypt_file, decrypt_file
import os

def main():
    # Test key generation
    print("Generating 2048-bit RSA key pair...")
    public_key, private_key = rsa_key_generation(2048)
    
    # Sanity-check outputs
    e, n = public_key
    d, n2 = private_key
    print(f"Public key: e={e}, n={n}")
    print(f"Private key: d={d}, n={n2}")
    assert n == n2, "Modulus mismatch"
    
    # Save keys to files
    save_key_to_file(public_key, 'public_key.txt')
    save_key_to_file(private_key, 'private_key.txt')
    print("Keys saved to public_key.txt and private_key.txt")
    
    # Define file paths relative to the script location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    original_file = os.path.join(script_dir, "test.pdf")
    encrypted_file = os.path.join(script_dir, "encrypted.bin")
    decrypted_file = os.path.join(script_dir, "decrypted.pdf")

    
    # Create a test file if it doesn't exist
    if not os.path.exists(original_file):
        with open(original_file, 'wb') as f:
            f.write(b"This is a test file for RSA-OAEP encryption and decryption.")
            print(f"Created test file: {original_file}")
    
    # Encrypt the file
    print(f"\nEncrypting {original_file} to {encrypted_file}...")
    encrypt_file(original_file, encrypted_file, 'public_key.txt')
    
    # Decrypt the file
    print(f"\nDecrypting {encrypted_file} to {decrypted_file}...")
    decrypt_file(encrypted_file, decrypted_file, 'private_key.txt')
    
    # Verify the decryption
    with open(original_file, 'rb') as f1, open(decrypted_file, 'rb') as f2:
        original_content = f1.read()
        decrypted_content = f2.read()
        
        if original_content == decrypted_content:
            print("\nSUCCESS: Decrypted file matches the original file!")
        else:
            print("\nERROR: Decrypted file does not match the original file!")

def compare_files(file1, file2):
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        content1 = f1.read()
        content2 = f2.read()
        
        size1 = len(content1)
        size2 = len(content2)
        
        print(f"File 1 size: {size1} bytes")
        print(f"File 2 size: {size2} bytes")
        
        if size1 != size2:
            print(f"Size mismatch: {size1} vs {size2} bytes")
            return
            
        # Find first difference
        for i in range(size1):
            if content1[i] != content2[i]:
                print(f"First difference at byte {i}: {content1[i]} vs {content2[i]}")
                context_start = max(0, i-10)
                context_end = min(size1, i+10)
                print(f"Context around difference:")
                print(f"Original: {content1[context_start:context_end]}")
                print(f"Decrypted: {content2[context_start:context_end]}")
                return
                
        print("Files are identical")

# Add to main.py after decryption
main()
script_dir = os.path.dirname(os.path.abspath(__file__))
original_file = os.path.join(script_dir, "test.pdf")
encrypted_file = os.path.join(script_dir, "encrypted.bin")
decrypted_file = os.path.join(script_dir,'decrypted.pdf')
compare_files(original_file, decrypted_file)

