import os
import pytesseract
from PIL import Image

# If needed on Windows, uncomment this and set your correct path:
# pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"


def extract_text_from_image(image_path: str) -> str:
    if not os.path.exists(image_path):
        return ""

    try:
        image = Image.open(image_path)
        text = pytesseract.image_to_string(image)
        return text.strip()
    except Exception:
        return ""