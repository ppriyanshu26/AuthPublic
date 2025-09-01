"""
This script reads a QR code from an image, optionally encrypts the decoded data 
using AES-256, and allows the user to save the encrypted result to a file for later use.

Features:
- Reads QR codes from images using OpenCV.
- Validates user input (Y/N) for encryption and saving steps.
- Derives a secure AES-256 key from a passphrase.
- Encrypts the QR code data with a random IV for security.
- Optionally stores the platform name and encrypted data into a text file.
"""


import cv2
import re
import base64
import hashlib
import os
import sys
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
            sys.exit()
            
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    # Replace 'qrcode.png' with the path to your QR code image file
    data = read_qr_code_with_cv2('qrcode.png')

    while True:
        answer = input("Encrypt data(Y|N): ").strip().upper()
        if answer == "Y":
            break
        elif answer == "N":
            print("\n✅ Decoded Data:", data)
            sys.exit()
            break
        else:
            print("\nOnly Y or N allowed. Please try again.")
    
    pattern = re.compile(r'issuer=(\w+)', re.I)
    secret_key = getpass("Enter the encryption key (hidden): ").strip()

    try:
        platform = re.findall(pattern, data)[0]
        data = encrypt_aes256(data, secret_key)
        
        while True:
            answer = input("Add this platform to the app(Y|N): ").strip().upper()
            if answer == "Y":
                file_name = "encoded.txt"
                with open(file_name, "a") as f:
                    f.write(f"{platform}, {data}\n")
                print("Entry added")
                break
            elif answer == "N":
                print("\n✅ Encrypted Result:", data)
                break
            else:
                print("\nOnly Y or N allowed. Please try again.")

    except Exception as e:
        print(f"❌ Encryption failed: {e}")
    
   