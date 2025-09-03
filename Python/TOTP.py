"""
TOTP Authenticator v1.1.1
-------------------------
A secure desktop application (Tkinter-based) for managing Time-based One-Time Passwords (TOTPs).

Features:
    - AES-256 encryption/decryption for securely storing OTP secrets.
    - GitHub integration for fetching encrypted OTP data from a private repository.
    - Password-based application lock with SHA-256 hashing.
    - OTP list UI with live countdown timers and clipboard copy support.
    - Crypto utility for quick text encryption/decryption with the master key.
    - Password reset functionality with validation.
    - Encrypted local cache for authentication.

Files:
    - cache.txt   : Stores the hashed app password.
    - encoded.txt : Stores encrypted OTP entries (platform, encrypted URL).

Usage:
    - On first run, prompts the user to create a password.
    - On subsequent runs, requires password and decryption key to unlock.
    - Allows importing encrypted OTPs from GitHub.
    - Displays OTP codes in real time with automatic refresh.
    - Provides options to lock, reset password, manage GitHub tokens, and use a crypto utility.

Author: Priyanshu Priyam
"""

import tkinter as tk
import pyotp
import time
import pyperclip
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
import os
import sys
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import keyring
import getpass

# ------------------- Base Directory -------------------

if sys.platform == "win32":
    BASE_APP_DIR = os.getenv("APPDATA")  # Windows
elif sys.platform == "darwin":
    BASE_APP_DIR = os.path.expanduser("~/Library/Application Support")  # macOS
elif sys.platform.startswith("linux"):
    BASE_APP_DIR = os.path.expanduser("~/.local/share")  # Linux
else:
    BASE_APP_DIR = os.getcwd()  # Fallback for unknown platforms

# Create a folder for your app
APP_FOLDER = os.path.join(BASE_APP_DIR, "TOTP Authenticator")
os.makedirs(APP_FOLDER, exist_ok=True)

# File paths
CACHE_FILE = os.path.join(APP_FOLDER, "cache.txt")
ENCODED_FILE = os.path.join(APP_FOLDER, "encoded.txt")

frames = []
toast_label = None
canvas = None
inner_frame = None
decrypt_key = None
popup_window = None
SERVICE_NAME = "TOTP Authenticator"
USERNAME = getpass.getuser()

# ------------------- Utility -------------------
def load_otps_from_decrypted(decrypted_otps):
    return [(name.strip(), uri.strip()) for name, uri in decrypted_otps if "otpauth://" in uri]

def clean_uri(uri):
    parsed = urlparse(uri)
    query = parse_qs(parsed.query)
    label = unquote(parsed.path.split('/')[-1])
    if ':' in label:
        label_issuer, username = label.split(':', 1)
    else:
        label_issuer = username = label
    query_issuer = query.get("issuer", [label_issuer])[0]
    if label_issuer != query_issuer:
        query['issuer'] = [label_issuer]
    parsed = parsed._replace(query=urlencode(query, doseq=True))
    return urlunparse(parsed), label_issuer, username

def copy_and_toast(var, root):
    global toast_label
    pyperclip.copy(var.get())
    if toast_label: toast_label.destroy()
    toast_label = tk.Label(root, text="✅ Copied to clipboard", bg="#444", fg="white",
                           font=("Segoe UI", 10), padx=12, pady=6)
    toast_label.place(relx=0.5, rely=1.0, anchor='s')
    root.after(1500, toast_label.destroy)

def on_mousewheel(event):
    canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

def get_cache_value(key):
    if not os.path.exists(CACHE_FILE): return None
    with open(CACHE_FILE, "r") as f:
        for line in f:
            if line.startswith(f"{key}="):
                return line.strip().split("=", 1)[1]
    return None

def set_cache_value(key, value):
    lines = []
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f: lines = f.readlines()
    found = False
    with open(CACHE_FILE, "w") as f:
        for line in lines:
            if line.startswith(f"{key}="):
                f.write(f"{key}={value}\n")
                found = True
            else: f.write(line)
        if not found: f.write(f"{key}={value}\n")

def save_password(password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    keyring.set_password(SERVICE_NAME, USERNAME, hashed)

def get_stored_password():
    return keyring.get_password(SERVICE_NAME, USERNAME)

def lock_app(root, otp_entries):
    for widget in root.winfo_children():
        widget.destroy()
    build_lock_screen(root, otp_entries)

# ------------------- Encryption -------------------
def decrypt_aes256(ciphertext_b64, key_str):
    key = hashlib.sha256(key_str.encode()).digest()
    raw = base64.urlsafe_b64decode(ciphertext_b64)
    iv, ciphertext = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded_plaintext) + unpadder.finalize()).decode()

def encrypt_aes256(plaintext, key_str):
    key = hashlib.sha256(key_str.encode()).digest()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    ciphertext = cipher.encryptor().update(padded_data) + cipher.encryptor().finalize()
    return base64.urlsafe_b64encode(iv + ciphertext).decode()

def decode_encrypted_file():
    global decrypt_key
    if not decrypt_key: return []
    decrypted_otps = []
    try:
        with open(ENCODED_FILE, 'r') as infile:
            for line in infile:
                if ',' not in line: continue
                platform, encrypted_url = map(str.strip, line.split(',', 1))
                try: decrypted_otps.append((platform, decrypt_aes256(encrypted_url, decrypt_key)))
                except Exception: continue
    except FileNotFoundError: pass
    return decrypted_otps

# ------------------- GitHub -------------------
def download_github_file(url, token):
    parsed = urlparse(url)
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 5 or parts[2] != "blob": raise ValueError("Invalid GitHub blob URL")
    owner, repo, _, branch = parts[:4]
    file_path = "/".join(parts[4:])
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}?ref={branch}"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3.raw"}
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        with open(ENCODED_FILE, "w", encoding="utf-8") as f: f.write(response.text)
    else: raise Exception(f"Failed to fetch file: {response.status_code}")

# ------------------- Enter Key -------------------
def bind_enter(root, button):
    root.unbind_all("<Return>")
    root.bind_all("<Return>", lambda event: button.invoke())

# ------------------- Popups -------------------
def open_popup(func, title="Popup", size="370x300"):
    global popup_window
    if popup_window is not None and popup_window.winfo_exists():
        popup_window.lift()          
        popup_window.focus_force()   
        return popup_window
    popup = tk.Toplevel(root)
    popup_window = popup
    popup.title(title)
    popup.geometry(size)
    popup.configure(bg="#1e1e1e")
    popup.transient(root)
    popup.grab_set()
    root_x = root.winfo_x()
    root_y = root.winfo_y()
    root_w = root.winfo_width()
    root_h = root.winfo_height()
    win_w, win_h = map(int, size.split("x"))
    x = root_x + (root_w // 2 - win_w // 2)
    y = root_y + (root_h // 2 - win_h // 2)
    popup.geometry(f"{win_w}x{win_h}+{x}+{y}")

    def on_close():
        global popup_window
        popup_window = None
        popup.destroy()
    popup.protocol("WM_DELETE_WINDOW", on_close)
    func(popup)
    return popup

# ------------------- Reset Password -------------------
def reset_password(parent):
    parent.resizable(False, False)
    frame = tk.Frame(parent, bg="#1e1e1e")
    frame.pack(expand=True, fill="both")
    root.unbind_all("<Return>")

    def create_entry(label_text):
        tk.Label(frame, text=label_text, bg="#1e1e1e", fg="white", font=("Segoe UI",10,"bold")).pack(pady=(10,5))
        entry = tk.Entry(frame, show="*", font=("Segoe UI",10), justify="center")
        entry.pack()
        return entry

    current_entry = create_entry("Enter current password:")
    current_entry.focus_set()
    new_entry = create_entry("New password:")
    confirm_entry = create_entry("Confirm new password:")

    error_label = tk.Label(frame, text="", bg="#1e1e1e", fg="red", font=("Segoe UI",9))
    error_label.pack(pady=(10,0))

    def perform_reset():
        stored_hash = get_stored_password()
        current_hash = hashlib.sha256(current_entry.get().encode()).hexdigest()
        if current_hash != stored_hash:
            error_label.config(text="Incorrect current password")
        elif new_entry.get() != confirm_entry.get():
            error_label.config(text="New passwords do not match")
        elif len(new_entry.get()) < 4:
            error_label.config(text="Password too short (min 4 chars)")
        else:
            save_password(new_entry.get())
            parent.destroy()

    reset_btn = tk.Button(frame, text="Reset Password", command=perform_reset,
                          font=("Segoe UI",10), bg="#444", fg="white", relief="flat", activebackground="#666")
    reset_btn.pack(pady=12)
    bind_enter(root, reset_btn)

# ------------------- GitHub Credential -------------------
def build_github_credential_screen(parent, otp_entries):
    parent.resizable(False, False)
    frame = tk.Frame(parent, bg="#1e1e1e")
    frame.pack(expand=True, fill="both")
    root.unbind_all("<Return>")

    tk.Label(frame, text="🔗 Enter GitHub File URL", font=("Segoe UI",14,"bold"), bg="#1e1e1e", fg="white").pack(pady=(30,10))
    url_entry = tk.Entry(frame, font=("Segoe UI",10), justify="center", width=40)
    url_entry.pack(pady=(0,10)); url_entry.focus()
    tk.Label(frame, text="GitHub Access Token", font=("Segoe UI",10,"bold"), bg="#1e1e1e", fg="white").pack(pady=(20,5))
    token_entry = tk.Entry(frame, font=("Segoe UI",10), justify="center", show="*")
    token_entry.pack(pady=(0,10))
    error_label = tk.Label(frame, text="", fg="red", bg="#1e1e1e", font=("Segoe UI",9))
    error_label.pack()

    def save_url():
        url, token = url_entry.get().strip(), token_entry.get().strip()
        if not url.startswith("https://github.com/") or "/blob/" not in url: error_label.config(text="Invalid GitHub blob URL"); return
        if not token: error_label.config(text="Token required"); return
        try:
            download_github_file(url, token)
            otp_entries[:] = load_otps_from_decrypted(decode_encrypted_file())
            build_main_ui(root, otp_entries)
        except Exception as e:
            error_label.config(text=f"Download failed: {str(e)}")

    save_btn = tk.Button(frame, text="Save & Continue", font=("Segoe UI",10),
                         bg="#444", fg="white", relief="flat", activebackground="#666",
                         command=save_url)
    save_btn.pack(pady=20)
    bind_enter(root, save_btn)

# ------------------- Crypto -------------------
def open_crypto_screen(parent):
    parent.resizable(False, False)
    frame = tk.Frame(parent, bg="#1e1e1e")
    frame.pack(expand=True, fill="both")
    root.unbind_all("<Return>")

    tk.Label(frame, text="🔒 Crypto Utility", font=("Segoe UI",14,"bold"),
             bg="#1e1e1e", fg="white").pack(pady=(20,10))

    tk.Label(frame, text="Enter text:", font=("Segoe UI",10,"bold"),
             bg="#1e1e1e", fg="white").pack(pady=(5,2))

    input_entry = tk.Entry(frame, font=("Segoe UI",12), width=25)
    input_entry.pack(pady=(0,10))
    input_entry.focus_set()

    tk.Label(frame, text="Result:", font=("Segoe UI",10,"bold"),
             bg="#1e1e1e", fg="white").pack(pady=(5,2))

    output_var = tk.StringVar()
    tk.Entry(frame, textvariable=output_var, font=("Segoe UI",12),
             width=25, state="readonly").pack(pady=(0,10))

    error_label = tk.Label(frame, text="", fg="red", bg="#1e1e1e", font=("Segoe UI",9))
    error_label.pack(pady=(0,5))

    def encrypt_text():
        global decrypt_key
        if not decrypt_key:
            error_label.config(text="Decryption key not set!")
            return
        try:
            output_var.set(encrypt_aes256(input_entry.get(), decrypt_key))
            error_label.config(text="")
        except Exception as e:
            error_label.config(text=f"Error: {str(e)}")

    def decrypt_text():
        global decrypt_key
        if not decrypt_key:
            error_label.config(text="Decryption key not set!")
            return
        try:
            output_var.set(decrypt_aes256(input_entry.get(), decrypt_key))
            error_label.config(text="")
        except Exception as e:
            error_label.config(text=f"Error: {str(e)}")

    tk.Button(frame, text="Encrypt", font=("Segoe UI",10), bg="#28db73", fg="white",
              relief="flat", command=encrypt_text).pack(side="left", padx=20, pady=20, expand=True)

    tk.Button(frame, text="Decrypt", font=("Segoe UI",10), bg="#ff4d4d", fg="white",
              relief="flat", command=decrypt_text).pack(side="right", padx=20, pady=20, expand=True)

    tk.Button(frame, text="Copy Result", font=("Segoe UI",10), bg="#444", fg="white",
              relief="flat", command=lambda: copy_and_toast(output_var, parent)).pack(pady=(10,20))

# ------------------- Main UI -------------------
def build_main_ui(root, otp_entries):
    global canvas, inner_frame, frames
    for widget in root.winfo_children():
        widget.destroy()

    # ---- TOP FIXED BAR ----
    top_bar = tk.Frame(root, bg="#1e1e1e")
    top_bar.pack(side="top", fill="x")

    lock_btn = tk.Button(top_bar, text="🔒 Lock App", font=("Segoe UI", 9, "bold"),
                     bg="#444", fg="white", relief="flat", activebackground="#666",
                     command=lambda: lock_app(root, otp_entries))
    lock_btn.pack(pady=6)

    # ---- MAIN CONTENT ----
    outer_frame = tk.Frame(root, bg="#1e1e1e")
    outer_frame.pack(fill="both", expand=True)

    canvas_frame = tk.Frame(outer_frame, bg="#1e1e1e")
    canvas_frame.pack(side="top", fill="both", expand=True)

    canvas = tk.Canvas(canvas_frame, bg="#1e1e1e", highlightthickness=0)
    scrollbar = tk.Scrollbar(canvas_frame, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)

    inner_frame = tk.Frame(canvas, bg="#1e1e1e")
    canvas.create_window((0, 0), window=inner_frame, anchor="nw")
    inner_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda e: canvas.itemconfig("all", width=e.width))
    canvas.bind_all("<MouseWheel>", on_mousewheel)

    frames.clear()

    # ---- OTP LIST ----
    if not otp_entries:
        tk.Label(inner_frame, text="⚠️ No OTPs Loaded", font=("Segoe UI", 11, "bold"),
                 fg="red", bg="#1e1e1e").pack(pady=20)
    else:
        for display_name, uri in otp_entries:
            cleaned_uri, issuer, username = clean_uri(uri)
            totp_obj = pyotp.TOTP(pyotp.parse_uri(cleaned_uri).secret)

            card = tk.Frame(inner_frame, bg="#2b2b2b", padx=12, pady=12)
            card.pack(fill="x", padx=12, pady=10)

            tk.Label(card, text=display_name, font=("Segoe UI", 12, "bold"),
                     bg="#2b2b2b", fg="#ffffff", anchor="w").pack(fill="x")
            tk.Label(card, text=username, font=("Segoe UI", 9),
                     fg="#aaaaaa", bg="#2b2b2b", anchor="w").pack(fill="x")

            bottom = tk.Frame(card, bg="#2b2b2b")
            bottom.pack(fill="x", pady=(8, 0))

            code_var = tk.StringVar()
            tk.Label(bottom, textvariable=code_var, font=("Courier", 16, "bold"),
                     bg="#2b2b2b", fg="#00ffcc").pack(side="left")

            time_var = tk.StringVar()
            time_label = tk.Label(bottom, textvariable=time_var, font=("Segoe UI", 10, "bold"),
                                  bg="#2b2b2b", fg="#00ffcc")
            time_label.pack(side="left", padx=(10, 0))

            tk.Button(bottom, text="Copy", font=("Segoe UI", 9),
                      bg="#444", fg="white", activebackground="#666", relief="flat",
                      command=lambda v=code_var: copy_and_toast(v, root)).pack(side="right")

            frames.append({
                "totp": totp_obj,
                "code_var": code_var,
                "time_var": time_var,
                "time_label": time_label
            })

    # ---- FOOTER ----
    footer = tk.Frame(outer_frame, bg="#1e1e1e")
    footer.pack(side="bottom", fill="x")

    tk.Button(footer, text="🔄 Reset", font=("Segoe UI", 10),
              bg="#2b2b2b", fg="white", relief="flat", height=2,
              command=lambda: open_popup(reset_password, title="Reset Password", size="300x300")).pack(side="left", fill="x", expand=True)

    tk.Button(footer, text="🗝 Token", font=("Segoe UI", 10),
              bg="#2b2b2b", fg="white", relief="flat", height=2,
              command=lambda: open_popup(lambda p: build_github_credential_screen(p, otp_entries), title="GitHub Token")).pack(side="left", fill="x", expand=True)

    tk.Button(footer, text="⚙️ Crypto", font=("Segoe UI", 10),
              bg="#2b2b2b", fg="white", relief="flat", height=2,
              command=lambda: open_popup(open_crypto_screen, title="Crypto Utility", size="370x300")).pack(side="left", fill="x", expand=True)

    if otp_entries:
        update_totps(root)

def update_totps(root):
    for entry in frames:
        totp, code_var, time_var, time_label = entry["totp"], entry["code_var"], entry["time_var"], entry["time_label"]
        code, time_left = totp.now(), 30 - int(time.time()) % 30
        try:
            code_var.set(code)
            time_var.set(f"{time_left}s")
            color = "#28db73" if time_left>20 else "#ffcc00" if time_left>10 else "#ff4d4d"
            time_label.configure(fg=color)
        except tk.TclError: continue
    root.after(1000, lambda: update_totps(root))

# ------------------- Password Screens -------------------
def build_create_password_screen(root, otp_entries):
    frame = tk.Frame(root, bg="#1e1e1e"); frame.pack(expand=True)
    root.unbind_all("<Return>")
    tk.Label(frame, text="🔐 Create a Password", font=("Segoe UI",14,"bold"), bg="#1e1e1e", fg="white").pack(pady=(40,10))
    pwd1, pwd2 = tk.Entry(frame, show="*", font=("Segoe UI",12), width=20, justify="center"), tk.Entry(frame, show="*", font=("Segoe UI",12), width=20, justify="center")
    pwd1.pack(pady=(10,5)); pwd1.focus(); pwd2.pack(pady=(0,10))
    error_label = tk.Label(frame, text="", fg="red", bg="#1e1e1e", font=("Segoe UI",9)); error_label.pack()

    def submit_password():
        if pwd1.get() != pwd2.get(): error_label.config(text="Passwords do not match.")
        elif len(pwd1.get()) < 4: error_label.config(text="Password too short (min 4 chars).")
        else: save_password(pwd1.get()); frame.destroy(); build_lock_screen(root, otp_entries)

    submit_btn = tk.Button(frame, text="Save & Continue", font=("Segoe UI",10),
                           bg="#444", fg="white", relief="flat", activebackground="#666",
                           command=submit_password)
    submit_btn.pack(pady=10); bind_enter(root, submit_btn)

def check_password(root, entry, error_label, otp_entries, lock_frame, decrypt_entry):
    global decrypt_key
    stored_password = get_stored_password()
    entered_hash = hashlib.sha256(entry.get().encode()).hexdigest()
    
    # Check if password matches
    if entered_hash == stored_password:
        key_input = decrypt_entry.get().strip()
        
        # Check if decryption key is empty
        if len(key_input) < 8:
            error_label.config(text="❌ Decryption key is too short.")
            return
        
        decrypt_key = key_input
        lock_frame.destroy()
        
        if not os.path.exists(ENCODED_FILE):
            build_github_credential_screen(root, otp_entries)
        else:
            otp_entries[:] = load_otps_from_decrypted(decode_encrypted_file())
            build_main_ui(root, otp_entries)
    else:
        error_label.config(text="❌ Incorrect password")

def build_lock_screen(root, otp_entries):
    frame = tk.Frame(root, bg="#1e1e1e"); frame.pack(expand=True)
    root.unbind_all("<Return>")
    tk.Label(frame, text="🔒 Enter Password", font=("Segoe UI",14,"bold"), bg="#1e1e1e", fg="white").pack(pady=(30,10))
    entry = tk.Entry(frame, show="*", font=("Segoe UI",12), width=20, justify="center"); entry.pack(pady=(0,10)); entry.focus()
    tk.Label(frame, text="🔑 Decryption Key", font=("Segoe UI",10,"bold"), bg="#1e1e1e", fg="white").pack(pady=(10,5))
    decrypt_entry = tk.Entry(frame, show="*", font=("Segoe UI",12), width=20, justify="center"); decrypt_entry.pack(pady=(0,10))
    error_label = tk.Label(frame, text="", fg="red", bg="#1e1e1e", font=("Segoe UI",9)); error_label.pack()
    unlock_btn = tk.Button(frame, text="Unlock", font=("Segoe UI",10),
                           bg="#444", fg="white", relief="flat", activebackground="#666",
                           command=lambda: check_password(root, entry, error_label, otp_entries, frame, decrypt_entry))
    unlock_btn.pack(pady=10); bind_enter(root, unlock_btn)

# ------------------- Main -------------------
if __name__ == "__main__":
    root = tk.Tk()
    root.title("TOTP Authenticator v2.0.0")
    root.geometry("420x500")
    root.configure(bg="#1e1e1e")
    root.resizable(False, False)

    otp_entries = []
    if get_stored_password() is None:
        build_create_password_screen(root, otp_entries)
    else:
        build_lock_screen(root, otp_entries)

    root.mainloop()
