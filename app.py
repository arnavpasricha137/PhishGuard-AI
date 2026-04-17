import os
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename

from detector import (
    analyze_email_text,
    analyze_url,
    combine_results,
    allowed_file,
)
from ocr_module import extract_text_from_image

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8 MB

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)


@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        email_text = request.form.get("email_text", "").strip()
        url = request.form.get("url", "").strip()
        uploaded_file = request.files.get("image_file")

        email_analysis = {
            "score": 0,
            "label": "Not Provided",
            "reasons": [],
            "source": "Email/Text",
            "status": "Not Analyzed",
        }

        url_analysis = {
            "score": 0,
            "label": "Not Provided",
            "reasons": [],
            "source": "URL",
            "status": "Not Analyzed",
        }

        image_analysis = {
            "score": 0,
            "label": "Not Provided",
            "reasons": [],
            "source": "Screenshot/Image",
            "status": "Not Analyzed",
        }

        extracted_text = ""

        if email_text:
            email_analysis = analyze_email_text(email_text)
            email_analysis["status"] = "Analyzed"

        if url:
            url_analysis = analyze_url(url)
            url_analysis["status"] = "Analyzed"

        if uploaded_file and uploaded_file.filename:
            if allowed_file(uploaded_file.filename):
                filename = secure_filename(uploaded_file.filename)
                filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                uploaded_file.save(filepath)

                extracted_text = extract_text_from_image(filepath)

                if extracted_text.strip():
                    image_analysis = analyze_email_text(extracted_text)
                    image_analysis["source"] = "Screenshot/Image OCR"
                    image_analysis["status"] = "Analyzed"
                else:
                    image_analysis = {
                        "score": 0,
                        "label": "Unreadable Image",
                        "reasons": ["No readable text found in uploaded image."],
                        "source": "Screenshot/Image OCR",
                        "status": "Analyzed",
                    }
            else:
                image_analysis = {
                    "score": 0,
                    "label": "Invalid File",
                    "reasons": ["Only PNG, JPG, and JPEG files are allowed."],
                    "source": "Screenshot/Image",
                    "status": "Analyzed",
                }

        result = combine_results(email_analysis, url_analysis, image_analysis)
        result["email_analysis"] = email_analysis
        result["url_analysis"] = url_analysis
        result["image_analysis"] = image_analysis
        result["extracted_text"] = extracted_text

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)