"""
QR Tool - Scan, Generate, Encrypt, and Save QR Code Data

This application provides two main modes:
1. Scan & Encrypt QR Code:
   - Select an existing QR code image.
   - Decode the QR data using OpenCV.
   - Encrypt the data with AES-256 (using SHA-256 derived key).
   - Save the encrypted data to a file (encoded.txt) with a platform name.

2. Generate QR from Secret:
   - Enter Email, Secret Code, and Issuer.
   - Generate a TOTP-compatible QR code.
   - Save the generated QR as an image file.
   - Automatically redirect to Scan & Encrypt mode with the generated QR.

Features:
- AES-256 encryption with PKCS7 padding and CBC mode.
- QR code scanning via OpenCV (cv2.QRCodeDetector).
- QR code generation using the `qrcode` library.
- User-friendly interface built with Tkinter.
- Toast notifications for success/error messages.

Author: Priyanshu Priyam
"""

import cv2
import base64
import hashlib
import os
import qrcode
import urllib.parse
from tkinter import Tk, filedialog, Button, Label, Text, END, Frame
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# ---------- Encryption Helpers ----------
def derive_aes256_key(key_str):
    if len(key_str) < 8:
        raise ValueError("Key must be at least 8 characters long.")
    return hashlib.sha256(key_str.encode()).digest()

def encrypt_aes256(plaintext, key_str):
    key = derive_aes256_key(key_str)
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    result = base64.urlsafe_b64encode(iv + ciphertext).decode()
    return result

def read_qr_code_with_cv2(image_path):
    image = cv2.imread(image_path)
    if image is None:
        return None
    qr_detector = cv2.QRCodeDetector()
    decoded_data, points, _ = qr_detector.detectAndDecode(image)
    return decoded_data if decoded_data else None

# ---------- Toast ----------
def show_toast(message, color="#333"):
    toast_label.config(text=message, bg=color)
    toast_label.pack(fill="x", pady=(0, 10))
    toast_label.after(2500, toast_label.pack_forget)

# ---------- SCAN MODE ----------
def select_image():
    global file_path
    file_path = filedialog.askopenfilename(
        title="Select a QR Code Image",
        filetypes=[("Image files", "*.png;*.jpg;*.jpeg")]
    )
    if file_path:
        decoded = read_qr_code_with_cv2(file_path)
        if decoded:
            decoded_text.delete("1.0", END)
            decoded_text.insert(END, decoded)
            show_toast("✅ QR Code decoded!", "#228B22")
        else:
            show_toast("❌ No QR code found.", "#8B0000")

def encrypt_data():
    raw_data = decoded_text.get("1.0", END).strip()
    if not raw_data:
        show_toast("⚠️ No QR data to encrypt!", "#8B0000")
        return
    
    key_str = key_entry.get("1.0", END).strip()
    if not key_str:
        show_toast("⚠️ Enter an encryption key!", "#8B0000")
        return

    try:
        encrypted = encrypt_aes256(raw_data, key_str)
        encrypted_text.delete("1.0", END)
        encrypted_text.insert(END, encrypted)
        show_toast("🔒 Data encrypted!", "#228B22")
    except Exception as e:
        show_toast(f"❌ Encryption failed: {e}", "#8B0000")

def save_data():
    encrypted = encrypted_text.get("1.0", END).strip()
    if not encrypted:
        show_toast("⚠️ No encrypted data to save!", "#8B0000")
        return

    platform = platform_entry.get("1.0", END).strip()
    if not platform:
        show_toast("⚠️ Enter a platform name!", "#8B0000")
        return

    with open("encoded.txt", "a") as f:
        f.write(f"{platform}, {encrypted}\n")
    show_toast("💾 Saved to encoded.txt", "#228B22")

# ---------- GENERATE MODE SCREEN ----------
def open_generate_mode():
    for widget in frame.winfo_children():
        widget.destroy()

    styled_label("Email:").pack(anchor="w", pady=5)
    global email_entry, secret_entry, issuer_entry
    email_entry = Text(frame, height=2, wrap="word", bg="#2D2D2D", fg="white", insertbackground="white")
    email_entry.pack(fill="x", pady=5)

    styled_label("Secret Code:").pack(anchor="w", pady=5)
    secret_entry = Text(frame, height=2, wrap="word", bg="#2D2D2D", fg="white", insertbackground="white")
    secret_entry.pack(fill="x", pady=5)

    styled_label("Issuer:").pack(anchor="w", pady=5)
    issuer_entry = Text(frame, height=2, wrap="word", bg="#2D2D2D", fg="white", insertbackground="white")
    issuer_entry.pack(fill="x", pady=5)

    styled_button("➕ Generate QR", generate_qr).pack(pady=10)
    styled_button("⬅ Back", start_menu).pack(pady=10)

def generate_qr():
    email = email_entry.get("1.0", END).strip()
    secret = secret_entry.get("1.0", END).strip().replace(" ", "")
    issuer = issuer_entry.get("1.0", END).strip()

    if not (email and secret and issuer):
        show_toast("⚠️ All fields required!", "#8B0000")
        return

    # URL encode values
    label = f"{issuer}:{email}"
    label_encoded = urllib.parse.quote(label)
    issuer_encoded = urllib.parse.quote(issuer)

    # Build TOTP URI
    totp_url = f"otpauth://totp/{label_encoded}?secret={secret}&issuer={issuer_encoded}&algorithm=SHA1&digits=6&period=30"

    # Generate QR code
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10,border=4,)
    qr.add_data(totp_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    filename = f"{issuer}.png"
    img.save(filename)

    show_toast(f"📷 QR code saved as {filename}", "#228B22")

    # 🚀 Redirect to scan mode with generated QR as input
    def load_generated_qr():
        global file_path
        file_path = filename
        decoded = read_qr_code_with_cv2(file_path)
        if decoded:
            decoded_text.delete("1.0", END)
            decoded_text.insert(END, decoded)
            show_toast("✅ QR Code decoded!", "#228B22")
        else:
            show_toast("❌ Failed to decode generated QR.", "#8B0000")

    open_scan_mode(auto_select=False)   # don’t open dialog
    root.after(200, load_generated_qr)

def styled_label(text):
    return Label(frame, text=text, fg="white", bg="#1E1E1E", font=("Segoe UI", 11, "bold"))

def styled_button(text, cmd):
    return Button(frame, text=text, command=cmd, 
                  bg="#333", fg="white", activebackground="#555", activeforeground="white",
                  relief="flat", padx=10, pady=5, font=("Segoe UI", 10, "bold"))

# ---------- START MENU ----------
def start_menu():
    for widget in frame.winfo_children():
        widget.destroy()
    styled_label("Choose Mode:").pack(pady=20)
    styled_button("📷 Scan & Encrypt QR Code", open_scan_mode).pack(pady=10)
    styled_button("➕ Generate QR from Secret", open_generate_mode).pack(pady=10)

# ---------- SCAN MODE SCREEN ----------
def open_scan_mode(auto_select=True):
    for widget in frame.winfo_children():
        widget.destroy()

    styled_label("Decoded QR Data:").pack(anchor="w", pady=5)
    global decoded_text, platform_entry, key_entry, encrypted_text
    decoded_text = Text(frame, height=3, wrap="word", bg="#2D2D2D", fg="white", insertbackground="white")
    decoded_text.pack(fill="x", pady=5)

    styled_label("Platform Name:").pack(anchor="w", pady=5)
    platform_entry = Text(frame, height=1, wrap="word", bg="#2D2D2D", fg="white", insertbackground="white")
    platform_entry.pack(fill="x", pady=5)

    styled_label("Encryption Key:").pack(anchor="w", pady=5)
    key_entry = Text(frame, height=1, wrap="word", bg="#2D2D2D", fg="white", insertbackground="white")
    key_entry.pack(fill="x", pady=5)

    styled_label("Encrypted Data:").pack(anchor="w", pady=5)
    encrypted_text = Text(frame, height=3, wrap="word", bg="#2D2D2D", fg="white", insertbackground="white")
    encrypted_text.pack(fill="x", pady=5)

    styled_button("🔒 Encrypt Data", encrypt_data).pack(pady=5)
    styled_button("💾 Save to File", save_data).pack(pady=5)
    styled_button("⬅ Back", start_menu).pack(pady=15)

    # only open file dialog if not redirected from generate
    if auto_select:
        root.after(200, select_image)

# ---------- UI Layout ----------
root = Tk()
root.title("QR Tool v1.0.0")
root.geometry("600x550")
root.config(bg="#1E1E1E")
root.resizable(False, False)

toast_label = Label(root, text="", fg="white", font=("Segoe UI", 10, "bold"))

frame = Frame(root, bg="#1E1E1E")
frame.pack(fill="both", expand=True, padx=15, pady=15)

# Start with menu
start_menu()
root.mainloop()
