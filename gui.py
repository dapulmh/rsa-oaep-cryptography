import os
import tkinter as tk
from tkinter import filedialog, messagebox

# Import your cryptography modules and functions
from cryptolib.number_theory import *
from cryptolib.rsa_key_generator import *
from cryptolib.file_util import *
from cryptolib.rsa import encrypt_file, decrypt_file

def generate_keys_if_not_exists():
    if not (os.path.exists('public_key.txt') and os.path.exists('private_key.txt')):
        print("Generating 2048-bit RSA key pair...")
        public_key, private_key = rsa_key_generation(2048)
        save_key_to_file(public_key, 'public_key.txt')
        save_key_to_file(private_key, 'private_key.txt')
        print("Keys saved to public_key.txt and private_key.txt")
    else:
        print("Keys already exist. Using the existing key pair.")

def encrypt_file_gui():

    input_file = filedialog.askopenfilename(title="Select a file to encrypt")
    if not input_file:
        return  # User cancelled

    output_file = filedialog.asksaveasfilename(
        title="Save Encrypted File As", defaultextension=".bin"
    )
    if not output_file:
        return  # User cancelled

    try:
        encrypt_file(input_file, output_file, 'public_key.txt')
        messagebox.showinfo("Encryption", f"File encrypted successfully!\nSaved as:\n{output_file}")
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

def decrypt_file_gui():
    input_file = filedialog.askopenfilename(
        title="Select a file to decrypt",
        filetypes=[("Encrypted Files", "*.bin"), ("All Files", "*.*")]
    )
    if not input_file:
        return  # User cancelled

    output_file = filedialog.asksaveasfilename(
        title="Save Decrypted File As", defaultextension=".txt"
    )
    if not output_file:
        return  # User cancelled

    try:
        decrypt_file(input_file, output_file, 'private_key.txt')
        messagebox.showinfo("Decryption", f"File decrypted successfully!\nSaved as:\n{output_file}")
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

def main_gui():
    # Generate keys automatically if they do not already exist.
    generate_keys_if_not_exists()

    # Create the main window.
    root = tk.Tk()
    root.title("RSA Encryption/Decryption GUI")
    root.geometry("350x180")

    # Display an instruction label.
    label = tk.Label(root, text="Select an operation:", font=("Helvetica", 14))
    label.pack(pady=15)

    # Create Encrypt and Decrypt buttons.
    encrypt_button = tk.Button(root, text="Encrypt File", command=encrypt_file_gui, width=20)
    encrypt_button.pack(pady=5)

    decrypt_button = tk.Button(root, text="Decrypt File", command=decrypt_file_gui, width=20)
    decrypt_button.pack(pady=5)

    # Start the GUI loop.
    root.mainloop()

if __name__ == '__main__':
    main_gui()