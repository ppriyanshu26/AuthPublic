import cv2
import base64
import hashlib
import os
from getpass import getpass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Derive AES-256 key from string
def derive_aes256_key(key_str):
    if len(key_str) < 8:
        raise ValueError("Key must be at least 8 characters long.")
    return hashlib.sha256(key_str.encode()).digest()

# Encrypt string using AES-256 (CBC mode with PKCS7 padding)
def encrypt_aes256(plaintext, key_str):
    key = derive_aes256_key(key_str)
    iv = os.urandom(16)  # Generate random IV

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    result = base64.urlsafe_b64encode(iv + ciphertext).decode()
    return result

# Read the image using OpenCV
def read_qr_code_with_cv2(image_path):
    try:
        image = cv2.imread(image_path)
        if image is None:
            print(f"Error: Could not load image from {image_path}")
            return
        qr_detector = cv2.QRCodeDetector()
        decoded_data, points, _ = qr_detector.detectAndDecode(image)
        if decoded_data:
            print("QR decoded")
            return decoded_data
        else:
            print("No QR code found in the image.")
            
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    # Replace 'qrcode.png' with the path to your QR code image file
    data = read_qr_code_with_cv2('images\\Hostinger.png')
    secret_key = getpass("Enter the encryption key (hidden): ").strip()
    try:
        encrypted_output = encrypt_aes256(data, secret_key)
        print("\n✅ Encrypted Result:\n", encrypted_output)
    except Exception as e:
        print(f"❌ Encryption failed: {e}")