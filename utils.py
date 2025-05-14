import cv2
from pyzbar.pyzbar import decode

def decode_qr_code(image_path):
    img = cv2.imread(image_path)
    decoded_objects = decode(img)
    if decoded_objects:
        return decoded_objects[0].data.decode('utf-8')
    return None
