import base64
import hashlib
import os
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Derive AES-256 key from string
def derive_aes256_key(key_str: str) -> bytes:
    if len(key_str) < 8:
        raise ValueError("Key must be at least 8 characters long.")
    return hashlib.sha256(key_str.encode()).digest()

# Encrypt string using AES-256 (CBC mode with PKCS7 padding)
def encrypt_aes256(plaintext: str, key_str: str) -> str:
    key = derive_aes256_key(key_str)
    iv = os.urandom(16)  # Generate random IV

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Prepend IV to ciphertext and encode in base64 (URL safe)
    result = base64.urlsafe_b64encode(iv + ciphertext).decode()
    return result

if __name__ == "__main__":
    plaintext_input = input("Enter the text to encrypt: ").strip()
    secret_key = getpass("Enter the encryption key (hidden): ").strip()

    try:
        encrypted_output = encrypt_aes256(plaintext_input, secret_key)
        print("\n✅ Encrypted Result:\n", encrypted_output)
    except Exception as e:
        print(f"❌ Encryption failed: {e}")
