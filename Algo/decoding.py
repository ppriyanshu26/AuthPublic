import base64
import requests
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Read keys.txt with format: key: value
def read_keys(file_path='keys.txt'):
    keys = {}
    with open(file_path, 'r') as f:
        for line in f:
            if ':' in line:
                k, v = line.strip().split(':', 1)
                keys[k.strip()] = v.strip()
    return keys

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

# Fetch file content from GitHub private repo
def get_file_from_github(username, token, repo_owner, repo_name, file_path):
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/contents/{file_path}"
    headers = {'Authorization': f'token {token}'}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    content = response.json()['content']
    return base64.b64decode(content).decode('utf-8')

# Extract the decryption key from keys.txt
def read_key_from_file(filepath='keys.txt') -> str:
    with open(filepath, 'r') as f:
        for line in f:
            if line.startswith("key:"):
                return line.split(":", 1)[1].strip()
    raise ValueError("Key not found in keys.txt")

# Process encrypted URL using the stored key
def process_encrypted_url(encrypted_url):
    key_str = read_key_from_file()
    return decrypt_aes256(encrypted_url, key_str)

# MAIN
if __name__ == "__main__":
    keys = read_keys()

    username = keys['username']
    token = keys['token']
    repo_owner = keys['repo_owner']
    repo_name = keys['repo_name']
    file_path = keys['file_path']

    try:
        raw_data = get_file_from_github(username, token, repo_owner, repo_name, file_path)
    except Exception:
        print("❌ Failed to fetch file: Internet issue or the token might have expired.")
        exit(1)

    # Write decrypted output
    with open('otp.txt', 'w') as outfile:
        for line in raw_data.splitlines():
            if ',' not in line:
                continue  # skip malformed lines
            platform, encrypted_url = map(str.strip, line.split(',', 1))
            try:
                decrypted_url = process_encrypted_url(encrypted_url)
                outfile.write(f"{platform}, {decrypted_url}\n")
            except Exception as e:
                outfile.write(f"{platform}, ERROR: {str(e)}\n")
