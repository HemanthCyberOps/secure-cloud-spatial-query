"""
Central configuration loaded from environment variables / .env file.
All servers import from here — no more scattered os.getenv() calls.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Locate and load the .env file that lives at the project root
_PROJECT_ROOT = Path(__file__).resolve().parents[2]  # backend/config → backend → project root
load_dotenv(_PROJECT_ROOT / ".env", override=True)

# ── Runtime environment ────────────────────────────────────────────────────────
IS_CLOUD: bool = os.getenv("IS_CLOUD", "false").lower() == "true"

# ── Redis ──────────────────────────────────────────────────────────────────────
REDIS_HOST: str = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT: int = int(os.getenv("REDIS_PORT", 6379))
REDIS_PASSWORD: str | None = os.getenv("REDIS_PASSWORD") or None   # None if empty string
USE_SSL: bool = IS_CLOUD

# ── Server ports ───────────────────────────────────────────────────────────────
SERVER_0_PORT: int = int(os.getenv("SERVER_0_PORT", 5000))
SERVER_1_PORT: int = int(os.getenv("SERVER_1_PORT", 5001))
SERVER_2_PORT: int = int(os.getenv("SERVER_2_PORT", 5002))

# ── Inter-service URLs ─────────────────────────────────────────────────────────
SERVER_2_URL: str = os.getenv("SERVER_2_URL", f"http://localhost:{SERVER_2_PORT}")

# ── Paillier key storage ───────────────────────────────────────────────────────
KEYS_DIR: Path = _PROJECT_ROOT / os.getenv("KEYS_DIR", "keys")
PUBLIC_KEY_PATH: Path  = KEYS_DIR / "public_key.pkl"
PRIVATE_KEY_PATH: Path = KEYS_DIR / "private_key.pkl"

# ── Dataset ────────────────────────────────────────────────────────────────────
DATASET_PATH: Path = _PROJECT_ROOT / "backend" / "dataset" / "reduced_healthcare_dataset.csv"

# ── Bloom filter ───────────────────────────────────────────────────────────────
BLOOM_FILTER_PATH: Path = _PROJECT_ROOT / "keys" / "bloom_filter.pkl"
