import qrcode
import urllib.parse

# Ask user for inputs
email = input("Enter your email: ").strip()
secret = input("Enter your secret code: ").strip().replace(" ", "")
issuer = input("Enter the issuer (e.g., GitHub, Google): ").strip()

# URL encode values (in case of special characters)
label = f"{issuer}:{email}"
label_encoded = urllib.parse.quote(label)
issuer_encoded = urllib.parse.quote(issuer)

# Build TOTP URI
totp_url = f"otpauth://totp/{label_encoded}?secret={secret}&issuer={issuer_encoded}&algorithm=SHA1&digits=6&period=30"
print("\n✅ Your TOTP URL:")
print(totp_url)

# Generate QR code
qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_H,
    box_size=10,
    border=4,
)

qr.add_data(totp_url)
qr.make(fit=True)

img = qr.make_image(fill_color="black", back_color="white")

# Save QR code
filename = "totp_qrcode.png"
img.save(filename)
print(f"\n📷 QR code saved as: {filename}")
