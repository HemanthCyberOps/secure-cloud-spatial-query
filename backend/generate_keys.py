"""
One-time key generation script.

Run this ONCE before starting any server:
    python backend/generate_keys.py

It creates:
    keys/public_key.pkl
    keys/private_key.pkl
    keys/bloom_filter.pkl   (built from the dataset)
"""
import sys
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("generate_keys")

# Allow imports from backend/
sys.path.append(str(Path(__file__).resolve().parent))

from config.settings import PUBLIC_KEY_PATH, PRIVATE_KEY_PATH, DATASET_PATH, BLOOM_FILTER_PATH
from shared.paillier import _get_or_create_keys
from shared.BloomFilter import load_or_create_bloom_filter
import pandas as pd


def main():
    logger.info("── Step 1: Paillier keypair ──────────────────────────────────")
    pub, priv = _get_or_create_keys()
    logger.info("   public_key  → %s", PUBLIC_KEY_PATH)
    logger.info("   private_key → %s", PRIVATE_KEY_PATH)

    logger.info("── Step 2: Bloom filter ──────────────────────────────────────")
    if not Path(DATASET_PATH).exists():
        logger.error("Dataset not found at %s — skipping Bloom filter build.", DATASET_PATH)
        return

    df = pd.read_csv(DATASET_PATH)
    logger.info("   Dataset loaded: %d rows, %d columns", len(df), len(df.columns))

    # Force rebuild
    if Path(BLOOM_FILTER_PATH).exists():
        Path(BLOOM_FILTER_PATH).unlink()
        logger.info("   Removed old bloom_filter.pkl")

    load_or_create_bloom_filter(BLOOM_FILTER_PATH, df)
    logger.info("   bloom_filter → %s", BLOOM_FILTER_PATH)

    logger.info("✅ All keys and filters generated successfully.")


if __name__ == "__main__":
    main()
