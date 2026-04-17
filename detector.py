import re
from urllib.parse import urlparse


ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def normalize_score(score: int) -> int:
    return max(0, min(score, 100))


def get_label(score: int) -> str:
    if score >= 75:
        return "Phishing"
    if score >= 45:
        return "Suspicious"
    return "Safe"


def analyze_email_text(text: str) -> dict:
    score = 0
    reasons = []
    text_lower = text.lower()

    suspicious_keywords = {
        "urgent": 10,
        "immediately": 10,
        "verify your account": 18,
        "click here": 14,
        "login now": 15,
        "update your account": 15,
        "confirm your identity": 18,
        "bank": 8,
        "password": 12,
        "otp": 10,
        "suspended": 14,
        "reset your password": 18,
        "unusual activity": 14,
        "act now": 10,
        "payment failed": 10,
        "gift card": 10,
        "claim reward": 12,
        "lottery": 12,
        "free": 5,
    }

    for keyword, weight in suspicious_keywords.items():
        if keyword in text_lower:
            score += weight
            reasons.append(f'Suspicious phrase detected: "{keyword}"')

    urgency_patterns = [
        r"within \d+ hours",
        r"within \d+ minutes",
        r"your account will be closed",
        r"failure to respond",
        r"immediate action required",
    ]
    for pattern in urgency_patterns:
        if re.search(pattern, text_lower):
            score += 10
            reasons.append("Urgency-based social engineering language detected")

    if "dear customer" in text_lower or "dear user" in text_lower:
        score += 8
        reasons.append("Generic greeting detected")

    exclamations = text.count("!")
    if exclamations >= 3:
        score += 8
        reasons.append("Excessive punctuation detected")

    if "http://" in text_lower or "https://" in text_lower or "www." in text_lower:
        score += 10
        reasons.append("Link found in message body")

    credential_phrases = [
        "enter your password",
        "share your otp",
        "verify your bank details",
        "confirm card details",
    ]
    for phrase in credential_phrases:
        if phrase in text_lower:
            score += 20
            reasons.append(f'Credential-harvesting phrase detected: "{phrase}"')

    if "password" in text_lower and "click" in text_lower:
        score += 15
        reasons.append("Password + click combination indicates phishing intent")

    if "bank" in text_lower and ("verify" in text_lower or "login" in text_lower):
        score += 15
        reasons.append("Financial verification pattern detected")

    score = normalize_score(score)
    label = get_label(score)

    if not reasons and text.strip():
        reasons.append("No major phishing indicators detected in text")

    return {
        "score": score,
        "label": label,
        "reasons": reasons,
        "source": "Email/Text",
    }


def analyze_url(url: str) -> dict:
    score = 0
    reasons = []
    url = url.strip()

    if not url:
        return {
            "score": 0,
            "label": "Not Provided",
            "reasons": [],
            "source": "URL",
        }

    parsed = urlparse(url if url.startswith(("http://", "https://")) else "http://" + url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full_url = (parsed.scheme + "://" + parsed.netloc + parsed.path).lower()

    suspicious_shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "cutt.ly"]
    suspicious_words = ["login", "verify", "secure", "update", "account", "banking", "signin"]
    brand_targets = ["paypal", "amazon", "google", "microsoft", "instagram", "facebook", "netflix", "bank"]

    if "@" in url:
        score += 25
        reasons.append("URL contains '@' symbol, often used to mislead users")

    if len(url) > 75:
        score += 12
        reasons.append("Very long URL detected")

    if domain.count("-") >= 2:
        score += 10
        reasons.append("Excessive hyphens in domain")

    if any(shortener in domain for shortener in suspicious_shorteners):
        score += 20
        reasons.append("Shortened URL detected")

    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 20
        reasons.append("IP address used instead of domain name")

    if domain.count(".") >= 3:
        score += 10
        reasons.append("Too many subdomains detected")

    for word in suspicious_words:
        if word in full_url:
            score += 7
            reasons.append(f'Suspicious URL keyword found: "{word}"')

    for brand in brand_targets:
        if brand in full_url and not domain.endswith(f"{brand}.com"):
            score += 12
            reasons.append(f'Possible brand spoofing attempt involving "{brand}"')

    if parsed.scheme != "https":
        score += 10
        reasons.append("URL is not using HTTPS")

    if "%" in full_url:
        score += 8
        reasons.append("Encoded characters found in URL")

    if path.count("//") >= 1:
        score += 8
        reasons.append("Unusual redirect-like path structure detected")

    score = normalize_score(score)
    label = get_label(score)

    if not reasons:
        reasons.append("No major phishing indicators detected in URL")

    return {
        "score": score,
        "label": label,
        "reasons": reasons,
        "source": "URL",
    }


def combine_results(email_analysis, url_analysis, image_analysis):
    email_score = email_analysis.get("score", 0)
    url_score = url_analysis.get("score", 0)
    image_score = image_analysis.get("score", 0)

    scores = [email_score, url_score, image_score]

    # Base weighted score
    weighted_score = int(
        (0.3 * email_score) +
        (0.5 * url_score) +
        (0.2 * image_score)
    )

    # 🔥 CRITICAL: Take max signal into account
    max_score = max(scores)

    # Final score = combine both
    final_score = int((weighted_score + max_score) / 2)

    # 🔥 Strong phishing overrides
    if url_score >= 60:
        final_score = max(final_score, 70)

    if "paypal" in str(url_analysis.get("reasons")).lower():
        final_score = max(final_score, 75)

    if "password" in str(email_analysis.get("reasons")).lower():
        final_score = max(final_score, 75)

    if image_score >= 70:
        final_score = max(final_score, 75)

    # Normalize
    final_score = min(100, final_score)

    # Label
    if final_score >= 75:
        label = "Phishing"
    elif final_score >= 45:
        label = "Suspicious"
    else:
        label = "Safe"

    # Combine reasons
    all_reasons = []
    for section in [email_analysis, url_analysis, image_analysis]:
        for reason in section.get("reasons", []):
            if reason not in all_reasons:
                all_reasons.append(reason)

    if not all_reasons:
        all_reasons.append("No strong phishing indicators found")

    return {
        "final_score": final_score,
        "final_label": label,
        "confidence": final_score,
        "all_reasons": all_reasons
    }
    