import base64
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Derive AES-256 key
def derive_aes256_key(key_str: str) -> bytes:
    if len(key_str) < 8:
        raise ValueError("Key must be at least 8 characters long.")
    return hashlib.sha256(key_str.encode()).digest()

# Decrypt function
def decrypt_aes256(ciphertext_b64: str, key_str: str) -> str:
    key = derive_aes256_key(key_str)
    raw = base64.urlsafe_b64decode(ciphertext_b64)
    iv = raw[:16]
    ciphertext = raw[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode()

# Read the key from keys.txt
def read_key_from_file(filepath='keys.txt') -> str:
    with open(filepath, 'r') as f:
        for line in f:
            if line.startswith("key:"):
                return line.split(":", 1)[1].strip()
    raise ValueError("Key not found in keys.txt")

# Main OTP decryptor
def process_encrypted_url(encrypted_url):
    key_str = read_key_from_file()
    return decrypt_aes256(encrypted_url, key_str)

# Main script
if __name__ == "__main__":
    with open('encoded.txt', 'r') as infile, open('otp.txt', 'w') as outfile:
        for line in infile:
            if ',' not in line:
                continue  # skip malformed lines
            platform, encrypted_url = map(str.strip, line.split(',', 1))
            try:
                decrypted_url = process_encrypted_url(encrypted_url)
                outfile.write(f"{platform}, {decrypted_url}\n")
            except Exception as e:
                outfile.write(f"{platform}, ERROR: {str(e)}\n")
