# rsa-oaep-cryptography

This repository belong to dapul &amp; rafi for cyptography course assignment

<pre>
rsa_oaep_project/
│
├── cryptolib/
│   ├── __init__.py
│   ├── number_theory.py      # primality tests, egcd, modinv
│   ├── rsa_key_generator.py  # RSA key pair generation
│   ├── oaep.py               # MGF1, oaep_encode/decode
│   ├── file_util.py          # Key file reading/writing utilities
│   └── rsa.py                # file chunking, encryption/decryption operations
│
└── gui.py                    # Tkinter GUI interface
</pre>

**How to run our program**

1. Run cryptolib/gui.py

**Output format of key**

Public key

*e_hex,n_hex*

Private key

*d_hex,n_hex*
