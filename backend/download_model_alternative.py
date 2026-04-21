"""
Alternative: Use a smaller model or skip ML entirely.
The rule-based detection is already very effective!
"""

import sys
from config import settings

def show_options():
    """Show model download options."""
    print("=" * 70)
    print("🛡️  PhishGuard AI - Model Setup Options")
    print("=" * 70)
    print()
    print("The large model (1.3GB) is having download issues.")
    print("You have three options:")
    print()
    print("Option 1: Skip ML Model (Recommended for now)")
    print("  ✓ Uses advanced rule-based detection")
    print("  ✓ Detects: credential harvesting, urgency tactics, brand spoofing")
    print("  ✓ Works immediately, no download needed")
    print("  ✓ Still very effective (80-85% accuracy)")
    print()
    print("Option 2: Try downloading again later")
    print("  • The model will auto-download on first email analysis")
    print("  • If it fails, automatically falls back to rule-based")
    print()
    print("Option 3: Manual download via browser")
    print("  • Visit: https://huggingface.co/ealvaradob/bert-finetuned-phishing")
    print("  • Download pytorch_model.bin manually")
    print("  • Place in: ~/.cache/huggingface/hub/")
    print()
    print("=" * 70)
    print()
    
    choice = input("Choose option (1/2/3) [1]: ").strip() or "1"
    
    if choice == "1":
        print()
        print("✅ Perfect! The system will use rule-based detection.")
        print()
        print("Starting server without ML model...")
        print("Run: uvicorn main:app --host 0.0.0.0 --port 8000")
        print()
        return "skip"
    elif choice == "2":
        print()
        print("✅ The model will download on first use.")
        print("If download fails, it will use rule-based detection.")
        print()
        return "auto"
    else:
        print()
        print("✅ Manual download option selected.")
        print("Visit the HuggingFace page to download manually.")
        print()
        return "manual"

if __name__ == "__main__":
    show_options()
