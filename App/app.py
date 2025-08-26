import tkinter as tk
import pyotp
import time
import pyperclip
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_FILE = os.path.join(BASE_DIR, "cache.txt")
ENCODED_FILE = os.path.join(BASE_DIR, "encoded.txt")

frames = []
toast_label = None
canvas = None
inner_frame = None
decrypt_key = None

# ------------------- Utility Functions -------------------

def load_otps_from_decrypted(decrypted_otps):
    otps = []
    for name, uri in decrypted_otps:
        if "otpauth://" in uri:
            otps.append((name.strip(), uri.strip()))
    return otps

def clean_uri(uri):
    parsed = urlparse(uri)
    query = parse_qs(parsed.query)
    label = unquote(parsed.path.split('/')[-1])
    if ':' in label:
        label_issuer, username = label.split(':', 1)
    else:
        label_issuer = label
        username = label
    query_issuer = query.get("issuer", [label_issuer])[0]
    if label_issuer != query_issuer:
        query['issuer'] = [label_issuer]
    parsed = parsed._replace(query=urlencode(query, doseq=True))
    return urlunparse(parsed), label_issuer, username

def copy_and_toast(var, root):
    global toast_label
    pyperclip.copy(var.get())
    if toast_label:
        toast_label.destroy()
    toast_label = tk.Label(root, text="✅ Copied to clipboard", bg="#444", fg="white",
                           font=("Segoe UI", 10), padx=12, pady=6)
    toast_label.place(relx=0.5, rely=1.0, anchor='s')
    root.after(1500, toast_label.destroy)

def on_mousewheel(event):
    canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

def get_cache_value(key):
    if not os.path.exists(CACHE_FILE):
        return None
    with open(CACHE_FILE, "r") as f:
        for line in f:
            if line.startswith(f"{key}="):
                return line.strip().split("=", 1)[1]
    return None

def set_cache_value(key, value):
    lines = []
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            lines = f.readlines()
    found = False
    with open(CACHE_FILE, "w") as f:
        for line in lines:
            if line.startswith(f"{key}="):
                f.write(f"{key}={value}\n")
                found = True
            else:
                f.write(line)
        if not found:
            f.write(f"{key}={value}\n")

def save_password(password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    set_cache_value("APP_PASSWORD", hashed)

def get_stored_password():
    return get_cache_value("APP_PASSWORD")

# ------------------- Encryption / Decryption -------------------

def decrypt_aes256(ciphertext_b64: str, key_str: str) -> str:
    key = hashlib.sha256(key_str.encode()).digest()
    raw = base64.urlsafe_b64decode(ciphertext_b64)
    iv = raw[:16]
    ciphertext = raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext.decode()

def encrypt_aes256(plaintext: str, key_str: str) -> str:
    key = hashlib.sha256(key_str.encode()).digest()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + ciphertext).decode()

def decode_encrypted_file() -> list:
    global decrypt_key
    decrypted_otps = []
    if not decrypt_key:
        return decrypted_otps
    try:
        with open(ENCODED_FILE, 'r') as infile:
            for line in infile:
                if ',' not in line:
                    continue
                platform, encrypted_url = map(str.strip, line.split(',', 1))
                try:
                    decrypted_url = decrypt_aes256(encrypted_url, decrypt_key)
                    decrypted_otps.append((platform, decrypted_url))
                except Exception:
                    continue
    except FileNotFoundError:
        pass
    return decrypted_otps

# ------------------- GitHub Download -------------------

def download_github_file(url, token):
    parsed = urlparse(url)
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 5 or parts[2] != "blob":
        raise ValueError("Invalid GitHub blob URL")
    owner, repo, _, branch = parts[:4]
    file_path = "/".join(parts[4:])
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}?ref={branch}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3.raw"
    }
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        with open(ENCODED_FILE, "w", encoding="utf-8") as f:
            f.write(response.text)
    else:
        raise Exception(f"Failed to fetch file: {response.status_code} - {response.text}")

# ------------------- UI Popups -------------------

def open_popup(func, title="Popup", size="400x300"):
    popup = tk.Toplevel(root)
    popup.title(title)
    popup.geometry(size)
    popup.configure(bg="#1e1e1e")
    func(popup)  # call function with popup as parent
    return popup

# ------------------- Password Management -------------------

def reset_password(parent):
    frame = tk.Frame(parent, bg="#1e1e1e")
    frame.pack(expand=True, fill="both")

    def create_entry(label_text):
        tk.Label(frame, text=label_text, bg="#1e1e1e", fg="white").pack(pady=(10, 5))
        entry = tk.Entry(frame, show="*", font=("Segoe UI", 10), justify="center")
        entry.pack()
        return entry

    current_entry = create_entry("Enter current password:")
    new_entry = create_entry("New password:")
    confirm_entry = create_entry("Confirm new password:")

    error_label = tk.Label(frame, text="", bg="#1e1e1e", fg="red", font=("Segoe UI", 9))
    error_label.pack(pady=(10, 0))

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
            parent.destroy()  # close popup after success

    tk.Button(frame, text="Reset Password", command=perform_reset,
              font=("Segoe UI", 10), bg="#444", fg="white", relief="flat",
              activebackground="#666").pack(pady=12)

def build_github_credential_screen(parent, otp_entries):
    frame = tk.Frame(parent, bg="#1e1e1e")
    frame.pack(expand=True, fill="both")

    tk.Label(frame, text="\U0001f517 Enter GitHub File URL", font=("Segoe UI", 14, "bold"),
             bg="#1e1e1e", fg="white").pack(pady=(30, 10))
    url_entry = tk.Entry(frame, font=("Segoe UI", 10), justify="center", width=40)
    url_entry.pack(pady=(0, 10))
    url_entry.focus()

    tk.Label(frame, text="GitHub Access Token", font=("Segoe UI", 10, "bold"),
             bg="#1e1e1e", fg="white").pack(pady=(20, 5))
    token_entry = tk.Entry(frame, font=("Segoe UI", 10), justify="center")
    token_entry.pack(pady=(0, 10))

    error_label = tk.Label(frame, text="", fg="red", bg="#1e1e1e", font=("Segoe UI", 9))
    error_label.pack()

    def save_url():
        url = url_entry.get().strip()
        token = token_entry.get().strip()
        if not url.startswith("https://github.com/") or "/blob/" not in url:
            error_label.config(text="Invalid GitHub blob URL")
            return
        if not token:
            error_label.config(text="Token required")
            return
        try:
            download_github_file(url, token)
            decrypted_otps = decode_encrypted_file()
            otp_entries[:] = load_otps_from_decrypted(decrypted_otps)
            build_main_ui(root, otp_entries)
            root.after(10, parent.destroy)

        except Exception as e:
            error_label.config(text=f"Download failed: {str(e)}")


    tk.Button(frame, text="Save & Continue", font=("Segoe UI", 10),
              bg="#444", fg="white", relief="flat", activebackground="#666",
              command=save_url).pack(pady=20)

def open_crypto_screen(parent):
    frame = tk.Frame(parent, bg="#1e1e1e")
    frame.pack(expand=True, fill="both")

    tk.Label(frame, text="🔒 Crypto Utility", font=("Segoe UI", 14, "bold"),
             bg="#1e1e1e", fg="white").pack(pady=(20, 10))
    tk.Label(frame, text="Enter text:", font=("Segoe UI", 10, "bold"),
             bg="#1e1e1e", fg="white").pack(pady=(5, 2))
    input_entry = tk.Entry(frame, font=("Segoe UI", 12), width=40)
    input_entry.pack(pady=(0, 10))

    tk.Label(frame, text="Result:", font=("Segoe UI", 10, "bold"),
             bg="#1e1e1e", fg="white").pack(pady=(5, 2))
    output_var = tk.StringVar()
    output_entry = tk.Entry(frame, textvariable=output_var, font=("Segoe UI", 12), width=40, state="readonly")
    output_entry.pack(pady=(0, 10))

    error_label = tk.Label(frame, text="", fg="red", bg="#1e1e1e", font=("Segoe UI", 9))
    error_label.pack(pady=(0, 5))

    def encrypt_text():
        if not decrypt_key:
            error_label.config(text="Decryption key not set!")
            return
        try:
            output_var.set(encrypt_aes256(input_entry.get(), decrypt_key))
            error_label.config(text="")
        except Exception as e:
            error_label.config(text=f"Error: {str(e)}")

    def decrypt_text():
        if not decrypt_key:
            error_label.config(text="Decryption key not set!")
            return
        try:
            output_var.set(decrypt_aes256(input_entry.get(), decrypt_key))
            error_label.config(text="")
        except Exception as e:
            error_label.config(text=f"Error: {str(e)}")

    tk.Button(frame, text="Encrypt", font=("Segoe UI", 10),
              bg="#28db73", fg="white", relief="flat", command=encrypt_text).pack(side="left", padx=20, pady=20, expand=True)
    tk.Button(frame, text="Decrypt", font=("Segoe UI", 10),
              bg="#ff4d4d", fg="white", relief="flat", command=decrypt_text).pack(side="right", padx=20, pady=20, expand=True)
    tk.Button(frame, text="Copy Result", font=("Segoe UI", 10),
              bg="#444", fg="white", relief="flat",
              command=lambda: copy_and_toast(output_var, parent)).pack(pady=(10, 20))

# ------------------- Main UI -------------------

def build_main_ui(root, otp_entries):
    global canvas, inner_frame, frames
    for widget in root.winfo_children():
        widget.destroy()

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
    if not otp_entries:
        tk.Label(inner_frame, text="⚠️ No OTPs Loaded", font=("Segoe UI", 11, "bold"), fg="red", bg="#1e1e1e").pack(pady=20)
    else:
        for display_name, uri in otp_entries:
            cleaned_uri, issuer, username = clean_uri(uri)
            totp_obj = pyotp.TOTP(pyotp.parse_uri(cleaned_uri).secret)
            card = tk.Frame(inner_frame, bg="#2b2b2b", padx=12, pady=12)
            card.pack(fill="x", padx=12, pady=10)

            tk.Label(card, text=display_name, font=("Segoe UI", 12, "bold"), bg="#2b2b2b", fg="#ffffff", anchor="w").pack(fill="x", anchor="w")
            tk.Label(card, text=username, font=("Segoe UI", 9), fg="#aaaaaa", bg="#2b2b2b", anchor="w").pack(fill="x", anchor="w")

            bottom = tk.Frame(card, bg="#2b2b2b")
            bottom.pack(fill="x", pady=(8, 0))

            code_var = tk.StringVar()
            tk.Label(bottom, textvariable=code_var, font=("Courier", 16, "bold"), bg="#2b2b2b", fg="#00ffcc").pack(side="left")
            time_var = tk.StringVar()
            time_label = tk.Label(bottom, textvariable=time_var, font=("Segoe UI", 10, "bold"), bg="#2b2b2b", fg="#00ffcc")
            time_label.pack(side="left", padx=(10, 0))
            tk.Button(bottom, text="Copy", font=("Segoe UI", 9), bg="#444", fg="white",
                      activebackground="#666", relief="flat",
                      command=lambda v=code_var: copy_and_toast(v, root)).pack(side="right")

            frames.append({
                "totp": totp_obj,
                "code_var": code_var,
                "time_var": time_var,
                "time_label": time_label
            })

    footer = tk.Frame(outer_frame, bg="#1e1e1e")
    footer.pack(side="bottom", fill="x")

    tk.Button(footer, text="\U0001f501 Reset", font=("Segoe UI", 10),
              bg="#2b2b2b", fg="white", relief="flat", height=2,
              command=lambda: open_popup(reset_password, title="Reset Password", size="300x300")).pack(side="left", fill="x", expand=True)

    tk.Button(footer, text="\U0001f6e0 Token", font=("Segoe UI", 10),
              bg="#2b2b2b", fg="white", relief="flat", height=2,
              command=lambda: open_popup(lambda p: build_github_credential_screen(p, otp_entries), title="GitHub Token")).pack(side="left", fill="x", expand=True)

    tk.Button(footer, text="⚙️ Crypto", font=("Segoe UI", 10),
              bg="#2b2b2b", fg="white", relief="flat", height=2,
              command=lambda: open_popup(open_crypto_screen, title="Crypto Utility", size="450x300")).pack(side="left", fill="x", expand=True)

    if otp_entries:
        update_totps(root)

def update_totps(root):
    for entry in frames:
        totp = entry["totp"]
        code = totp.now()
        time_left = 30 - int(time.time()) % 30
        try:
            entry["code_var"].set(code)
            entry["time_var"].set(f"{time_left}s")
            if time_left > 20:
                color = "#28db73"
            elif time_left > 10:
                color = "#ffcc00"
            else:
                color = "#ff4d4d"
            entry["time_label"].configure(fg=color)
        except tk.TclError:
            continue
    root.after(1000, lambda: update_totps(root))

# ------------------- Password Screens -------------------

def build_create_password_screen(root, otp_entries):
    frame = tk.Frame(root, bg="#1e1e1e")
    frame.pack(expand=True)

    tk.Label(frame, text="\U0001f510 Create a Password", font=("Segoe UI", 14, "bold"), bg="#1e1e1e", fg="white").pack(pady=(40, 10))
    pwd1 = tk.Entry(frame, show="*", font=("Segoe UI", 12), width=20, justify="center")
    pwd1.pack(pady=(10, 5))
    pwd1.focus()
    pwd2 = tk.Entry(frame, show="*", font=("Segoe UI", 12), width=20, justify="center")
    pwd2.pack(pady=(0, 10))
    error_label = tk.Label(frame, text="", fg="red", bg="#1e1e1e", font=("Segoe UI", 9))
    error_label.pack()

    def submit_password():
        if pwd1.get() != pwd2.get():
            error_label.config(text="Passwords do not match.")
        elif len(pwd1.get()) < 4:
            error_label.config(text="Password too short (min 4 chars).")
        else:
            save_password(pwd1.get())
            frame.destroy()
            build_lock_screen(root, otp_entries)

    tk.Button(frame, text="Save & Continue", font=("Segoe UI", 10),
              bg="#444", fg="white", relief="flat", activebackground="#666",
              command=submit_password).pack(pady=10)

def check_password(root, entry, error_label, otp_entries, lock_frame, decrypt_entry):
    global decrypt_key
    stored_password = get_stored_password()
    entered_hash = hashlib.sha256(entry.get().encode()).hexdigest()
    if entered_hash == stored_password:
        decrypt_key = decrypt_entry.get().strip()
        lock_frame.destroy()
        if not os.path.exists(ENCODED_FILE):
            build_github_credential_screen(root, otp_entries)
        else:
            decrypted_otps = decode_encrypted_file()
            otp_entries[:] = load_otps_from_decrypted(decrypted_otps)
            build_main_ui(root, otp_entries)
    else:
        error_label.config(text="Incorrect password")

def build_lock_screen(root, otp_entries):
    frame = tk.Frame(root, bg="#1e1e1e")
    frame.pack(expand=True)

    tk.Label(frame, text="\U0001f512 Enter Password", font=("Segoe UI", 14, "bold"), bg="#1e1e1e", fg="white").pack(pady=(30, 10))
    entry = tk.Entry(frame, show="*", font=("Segoe UI", 12), width=20, justify="center")
    entry.pack(pady=(0, 10))
    entry.focus()

    tk.Label(frame, text="🔑 Decryption Key", font=("Segoe UI", 10, "bold"), bg="#1e1e1e", fg="white").pack(pady=(10, 5))
    decrypt_entry = tk.Entry(frame, show="*", font=("Segoe UI", 12), width=20, justify="center")
    decrypt_entry.pack(pady=(0, 10))

    error_label = tk.Label(frame, text="", fg="red", bg="#1e1e1e", font=("Segoe UI", 9))
    error_label.pack()

    tk.Button(frame, text="Unlock", font=("Segoe UI", 10),
              bg="#444", fg="white", relief="flat", activebackground="#666",
              command=lambda: check_password(root, entry, error_label, otp_entries, frame, decrypt_entry)).pack(pady=10)

# ------------------- Main -------------------

if __name__ == "__main__":
    root = tk.Tk()
    root.title("TOTP Authenticator")
    root.geometry("420x500")
    root.configure(bg="#1e1e1e")
    root.resizable(False, False)

    otp_entries = []
    if get_stored_password() is None:
        build_create_password_screen(root, otp_entries)
    else:
        build_lock_screen(root, otp_entries)

    root.mainloop()
