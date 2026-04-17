# PhishGuard AI

PhishGuard AI is a phishing detection system developed for hackathon implementation round submission.

## Features
- Email/Text phishing detection
- URL phishing detection
- Screenshot/image phishing detection using OCR
- Final risk score and label
- Explainable output with reasons

## Project Structure
- app.py -> main Flask application
- detector.py -> phishing scoring logic
- ocr_module.py -> screenshot OCR module
- templates/index.html -> UI template
- requirements.txt -> dependencies

## How to Run

### 1. Install Python packages
pip install -r requirements.txt

### 2. Install Tesseract OCR
Windows:
- Download and install Tesseract OCR
- If needed, set path in ocr_module.py

### 3. Run the app
python app.py

### 4. Open in browser
http://127.0.0.1:5000

## Sample Inputs
### Phishing Text
Urgent! Your bank account has been suspended. Click here immediately to verify your identity and reset your password.

### Safe Text
Hello Arnav, your project meeting is scheduled for tomorrow at 10 AM. Please find the agenda attached.

### Suspicious URL
http://paypal-secure-login-update.bit.ly/verify-account

## Core Logic
The system checks:
- suspicious keywords
- urgency phrases
- credential stealing language
- risky URL structures
- OCR text extracted from screenshots

Then it combines all scores into a final verdict:
- Safe
- Suspicious
- Phishing