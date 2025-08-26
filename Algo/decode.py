import base64
import hashlib
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Derive AES-256 key from string
def derive_aes256_key(key_str: str) -> bytes:
    if len(key_str) < 8:
        raise ValueError("Key must be at least 8 characters long.")
    return hashlib.sha256(key_str.encode()).digest()

# Decrypt AES-256 (CBC mode with PKCS7 padding)
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

if __name__ == "__main__":
    encrypted_input = input("Enter the encrypted string: ").strip()
    secret_key = getpass("Enter the decryption key (hidden): ").strip()

    try:
        decrypted_output = decrypt_aes256(encrypted_input, secret_key)
        print("\n✅ Decrypted Result:\n", decrypted_output)
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
