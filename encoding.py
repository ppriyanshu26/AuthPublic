import base64
import urllib.parse
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Derive AES-256 key
def derive_aes256_key(key_str: str) -> bytes:
    if len(key_str) < 8:
        raise ValueError("Key must be at least 8 characters long.")
    return hashlib.sha256(key_str.encode()).digest()

# Encrypt function
def encrypt_aes256(plaintext: str, key_str: str) -> str:
    key = derive_aes256_key(key_str)
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.urlsafe_b64encode(iv + ciphertext).decode()

# Read the key from keys.txt
def read_key_from_file(filepath='keys.txt') -> str:
    with open(filepath, 'r') as f:
        for line in f:
            if line.startswith("key:"):
                return line.split(":", 1)[1].strip()
    raise ValueError("Key not found in keys.txt")

# Main OTP processing function
def process_otp_url(url):
    key_str = read_key_from_file()
    encrypted = encrypt_aes256(url, key_str)
    return encrypted

# Main script
if __name__ == "__main__":
    with open('otp.txt', 'r') as infile, open('encoded.txt', 'w') as outfile:
        for line in infile:
            if ',' not in line:
                continue  # skip bad lines
            platform, otp_url = map(str.strip, line.split(',', 1))
            modified_url = process_otp_url(otp_url)
            outfile.write(f"{platform}, {modified_url}\n")
