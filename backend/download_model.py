"""
Pre-download the ML model before starting the server.
This ensures the model is cached locally and ready to use.
"""

import os
import sys
import socket
from config import settings


def check_internet(host="huggingface.co", port=443, timeout=5):
    """Quick connectivity check to HuggingFace."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.create_connection((host, port))
        return True
    except (socket.error, OSError):
        return False


def is_fully_cached(model_name: str) -> bool:
    """Return True only if model weights (not just tokenizer files) are cached."""
    from pathlib import Path
    try:
        from huggingface_hub.constants import HF_HUB_CACHE
        cache_root = Path(HF_HUB_CACHE)
    except ImportError:
        cache_root = Path.home() / ".cache" / "huggingface" / "hub"

    slug = "models--" + model_name.replace("/", "--")
    snapshots_dir = cache_root / slug / "snapshots"

    if not snapshots_dir.is_dir():
        return False

    # Must have at least one snapshot with model weight files
    weight_globs = ["model.safetensors", "pytorch_model.bin",
                    "*.safetensors", "pytorch_model*.bin"]
    for snapshot in snapshots_dir.iterdir():
        if not snapshot.is_dir():
            continue
        for pattern in weight_globs:
            if any(snapshot.glob(pattern)):
                return True
    return False


def download_model():
    """Download and cache the phishing detection model with live progress."""
    model_name = settings.model_name

    print("=" * 60)
    print("📥 PhishGuard AI — Model Downloader")
    print("=" * 60)
    print(f"  Model : {model_name}")
    print(f"  Size  : ~440 MB (BERT fine-tuned)")
    print()

    # Already fully cached (has weights, not just tokenizer files)?
    if is_fully_cached(model_name):
        print("✅ Model already cached locally — nothing to download.")
        print(f"   Cache: ~/.cache/huggingface/hub/")
        return True
    else:
        print("⚠️  Incomplete cache detected (tokenizer only, missing model weights).")
        print("   Will re-download the model weights.")
        print()

    # Network check
    print("🌐 Checking connectivity to huggingface.co …", end=" ", flush=True)
    if not check_internet():
        print("FAILED")
        print("\n✗ Cannot reach huggingface.co.")
        print("  • Check your internet connection and try again.")
        return False
    print("OK")
    print()
    print("⬇  Downloading — progress bars will appear below.")
    print("   This may take several minutes on a slow connection.\n")

    try:
        from huggingface_hub import snapshot_download

        local_dir = snapshot_download(
            repo_id=model_name,
            repo_type="model",
        )

        print()
        print("=" * 60)
        print("✅ Model downloaded and cached successfully!")
        print("=" * 60)
        print(f"   Local path : {local_dir}")
        print()
        print("You can now start the server with:")
        print("  uvicorn main:app --host 0.0.0.0 --port 8000")
        print()
        return True

    except KeyboardInterrupt:
        print("\n⚠️  Download cancelled by user.")
        return False

    except Exception as e:
        print(f"\n✗ Download failed: {e}")
        print()
        print("Troubleshooting tips:")
        print("  1. Ensure you have ~1 GB of free disk space.")
        print("  2. Try:  pip install -U huggingface_hub transformers")
        print("  3. If the model requires auth, run:  huggingface-cli login")
        print("  4. The server will still run using rule-based detection without the model.")
        return False


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="PhishGuard model downloader")
    parser.add_argument("--check", action="store_true",
                        help="Check if model is fully cached without downloading")
    args = parser.parse_args()

    if args.check:
        from config import settings as _s
        cached = is_fully_cached(_s.model_name)
        if cached:
            print("✅ Model is fully cached and ready")
            sys.exit(0)
        else:
            print("❌ Model weights not cached — run: python download_model.py")
            sys.exit(1)
    else:
        success = download_model()
        sys.exit(0 if success else 1)
