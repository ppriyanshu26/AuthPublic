import qrcode

# Data to be encoded in the QR code
data = '''data'''

qr = qrcode.QRCode(
    version=1,
    error_correction=qrcode.constants.ERROR_CORRECT_H,
    box_size=10,
    border=4,
)

qr.add_data(data)
qr.make(fit=True)

img = qr.make_image(fill_color="black", back_color="white")

# Save the generated QR code image
img.save("qrcode.png")