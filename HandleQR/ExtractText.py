import cv2

def read_qr_code_with_cv2(image_path):
    try:
        # Read the image using OpenCV
        image = cv2.imread(image_path)
        if image is None:
            print(f"Error: Could not load image from {image_path}")
            return
        qr_detector = cv2.QRCodeDetector()
        decoded_data, points, _ = qr_detector.detectAndDecode(image)
        if decoded_data:
            print("Decoded QR Code Data:", decoded_data)
        else:
            print("No QR code found in the image.")
            
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == '__main__':
    # Replace 'qrcode.png' with the path to your QR code image file
    read_qr_code_with_cv2('qrcode.png')