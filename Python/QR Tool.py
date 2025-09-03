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
- AES-256 encryption with padding.
- QR code scanning via OpenCV.
- QR code generation.
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
import sys

# ---------- File Paths ----------
if sys.platform == "win32":
    BASE_APP_DIR = os.getenv("APPDATA")  # Windows
elif sys.platform == "darwin":
    BASE_APP_DIR = os.path.expanduser("~/Library/Application Support")  # macOS
elif sys.platform.startswith("linux"):
    BASE_APP_DIR = os.path.expanduser("~/.local/share")  # Linux
else:
    BASE_APP_DIR = os.getcwd()  # Fallback for unknown platforms

APP_FOLDER = os.path.join(BASE_APP_DIR, "TOTP Authenticator")
os.makedirs(APP_FOLDER, exist_ok=True)
ENCODED_FILE = os.path.join(APP_FOLDER, "encoded.txt")

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

# ---------- HORIZONTAL BUTTONS ----------
def add_horizontal_buttons(buttons):
    btn_frame = Frame(frame, bg="#1E1E1E")
    btn_frame.pack(pady=10)
    
    for text, cmd, color in buttons:
        Button(btn_frame, text=text, command=cmd, bg=color, fg="white", activebackground="#555", 
               activeforeground="white",relief="flat", padx=15, pady=7, 
               font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)

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

    with open(ENCODED_FILE, "a") as f:
        f.write(f"{platform}, {encrypted}\n")
    show_toast(f"💾 Saved to file", "#228B22")

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

    add_horizontal_buttons([
        ("➕ Generate QR", generate_qr, "#1E90FF"),
        ("⬅ Back", start_menu, "#FF4500")
    ])

def generate_qr():
    email = email_entry.get("1.0", END).strip()
    secret = secret_entry.get("1.0", END).strip().replace(" ", "")
    issuer = issuer_entry.get("1.0", END).strip()

    if not (email and secret and issuer):
        show_toast("⚠️ All fields required!", "#8B0000")
        return

    label = f"{issuer}:{email}"
    totp_url = f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"

    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=4,)
    qr.add_data(totp_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    filename = os.path.join(desktop_path, f"{issuer}.png")
    img.save(filename)

    show_toast(f"📷 QR code saved to Desktop as {issuer}.png", "#228B22")

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

    open_scan_mode(auto_select=False) 
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
    
    add_horizontal_buttons([
        ("📷 Scan & Encrypt QR Code", open_scan_mode, "#1E90FF"),
        ("➕ Generate QR from Secret", open_generate_mode, "#32CD32")
    ])

# ---------- SCAN MODE SCREEN ----------
def open_scan_mode(auto_select=True):
    for widget in frame.winfo_children():
        widget.destroy()

    styled_label("Decoded QR Data:").pack(anchor="w", pady=5)
    global decoded_text, platform_entry, key_entry, encrypted_text
    decoded_text = Text(frame, height=3, wrap="word", bg="#2D2D2D", fg="white", insertbackground="white")
    decoded_text.pack(fill="x", pady=5)

    styled_label("Platform Name:").pack(anchor="w", pady=5)
    platform_entry = Text(frame, height=2, wrap="word", bg="#2D2D2D", fg="white", insertbackground="white")
    platform_entry.pack(fill="x", pady=5)

    styled_label("Encryption Key:").pack(anchor="w", pady=5)
    key_entry = Text(frame, height=2, wrap="word", bg="#2D2D2D", fg="white", insertbackground="white")
    key_entry.pack(fill="x", pady=5)

    styled_label("Encrypted Data:").pack(anchor="w", pady=5)
    encrypted_text = Text(frame, height=3, wrap="word", bg="#2D2D2D", fg="white", insertbackground="white")
    encrypted_text.pack(fill="x", pady=5)

    add_horizontal_buttons([
        ("🔒 Encrypt Data", encrypt_data, "#FFA500"),
        ("💾 Save to File", save_data, "#32CD32"),
        ("⬅ Back", start_menu, "#FF4500")
    ])

    if auto_select:
        root.after(200, select_image)

# ---------- UI Layout ----------
root = Tk()
root.title("QR Tool v1.0.0")
root.geometry("500x500")
root.config(bg="#1E1E1E")
root.resizable(False, False)

toast_label = Label(root, text="", fg="white", font=("Segoe UI", 10, "bold"))

frame = Frame(root, bg="#1E1E1E")
frame.pack(fill="both", expand=True, padx=15, pady=15)

start_menu()
root.mainloop()
