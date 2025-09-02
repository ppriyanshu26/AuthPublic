import cv2
import base64
import hashlib
import os
from tkinter import Tk, filedialog, Button, Label, Text, Entry, END, Frame
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

# ---------- Toast Notification ----------
def show_toast(message, color="#333"):
    toast_label.config(text=message, bg=color)
    toast_label.pack(fill="x", pady=(0, 10))
    toast_label.after(2500, toast_label.pack_forget)  # auto-hide after 2.5s

# ---------- GUI Functions ----------
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

# ---------- Build Tkinter UI ----------
root = Tk()
root.title("QR Code Reader & Encryptor")
root.geometry("600x550")
root.config(bg="#1E1E1E")
root.resizable(False, False)

# Toast area
toast_label = Label(root, text="", fg="white", font=("Segoe UI", 10, "bold"))

# Frame for content
frame = Frame(root, bg="#1E1E1E")
frame.pack(fill="both", expand=True, padx=15, pady=15)

def styled_label(text):
    return Label(frame, text=text, fg="white", bg="#1E1E1E", font=("Segoe UI", 11, "bold"))

def styled_button(text, cmd):
    return Button(frame, text=text, command=cmd, 
                  bg="#333", fg="white", activebackground="#555", activeforeground="white",
                  relief="flat", padx=10, pady=5, font=("Segoe UI", 10, "bold"))

# Fields
styled_label("Decoded QR Data:").pack(anchor="w", pady=5)
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

# Buttons
styled_button("📂 Select QR Image", select_image).pack(pady=8)
styled_button("🔒 Encrypt Data", encrypt_data).pack(pady=5)
styled_button("💾 Save to File", save_data).pack(pady=5)

root.mainloop()
