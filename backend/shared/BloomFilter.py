"""
Bloom Filter implementation.

BloomFilter      — standard 3-D bit-array Bloom filter.
MultiLevelBloomFilter — wraps multiple BloomFilter levels for lower false-positive rate.
"""
import hashlib
import pickle
import logging
import numpy as np
from pathlib import Path

logger = logging.getLogger(__name__)


def _serialize(field: str, value) -> str:
    """Produce a stable, lowercase string key for a field-value pair."""
    return f"{str(field).lower().strip()}:{str(value).lower().strip()}"


class BloomFilter:
    """3-D Bloom filter — each hash maps to (x, y, z) in a 3-D bit array."""

    def __init__(self, dimensions=(50, 50, 50), num_hashes=7):
        self.dimensions = tuple(dimensions)
        self.num_hashes = num_hashes
        self.bit_array = np.zeros(self.dimensions, dtype=bool)

    def _hashes(self, key: str):
        """Yield (x, y, z) index tuples for the given key."""
        for seed in range(self.num_hashes):
            digest = int(
                hashlib.sha256(f"{seed}:{key}".encode()).hexdigest(), 16
            )
            x = (digest >> 0)  & 0xFFFF
            y = (digest >> 16) & 0xFFFF
            z = (digest >> 32) & 0xFFFF
            yield x % self.dimensions[0], y % self.dimensions[1], z % self.dimensions[2]

    def add(self, field: str, value) -> None:
        key = _serialize(field, value)
        for x, y, z in self._hashes(key):
            self.bit_array[x, y, z] = True

    def lookup(self, field: str, value) -> bool:
        key = _serialize(field, value)
        return all(self.bit_array[x, y, z] for x, y, z in self._hashes(key))

    # ── Persistence ────────────────────────────────────────────────────────────

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(
                {
                    "dimensions": self.dimensions,
                    "num_hashes": self.num_hashes,
                    "bit_array": self.bit_array,
                },
                f,
            )
        logger.info("✅ BloomFilter saved → %s", path)

    @classmethod
    def load(cls, path: Path) -> "BloomFilter":
        with open(path, "rb") as f:
            data = pickle.load(f)
        bf = cls(dimensions=data["dimensions"], num_hashes=data["num_hashes"])
        bf.bit_array = data["bit_array"]
        logger.info("✅ BloomFilter loaded ← %s", path)
        return bf


class MultiLevelBloomFilter:
    """
    Multi-level Bloom filter (HFil).

    Level 0 accepts everything.
    Level i (i > 0) only inserts if level i-1 already contains the element.
    A lookup requires ALL levels to return True.
    This reduces false positives compared to a single filter.
    """

    def __init__(self, levels=3, dimensions=(50, 50, 50), num_hashes=7):
        self.levels = levels
        self.filters = [BloomFilter(dimensions, num_hashes) for _ in range(levels)]

    def add(self, field: str, value) -> None:
        for i, bf in enumerate(self.filters):
            if i == 0 or self.filters[i - 1].lookup(field, value):
                bf.add(field, value)

    def lookup(self, field: str, value) -> bool:
        return all(bf.lookup(field, value) for bf in self.filters)

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self, f)
        logger.info("✅ MultiLevelBloomFilter saved → %s", path)

    @classmethod
    def load(cls, path: Path) -> "MultiLevelBloomFilter":
        with open(path, "rb") as f:
            obj = pickle.load(f)
        logger.info("✅ MultiLevelBloomFilter loaded ← %s", path)
        return obj


def load_or_create_bloom_filter(path: Path, dataset=None) -> MultiLevelBloomFilter:
    """
    Load a persisted MultiLevelBloomFilter from *path*, or build a fresh one
    from *dataset* (a pandas DataFrame) if the file doesn't exist / is corrupt.
    """
    if Path(path).exists():
        try:
            return MultiLevelBloomFilter.load(path)
        except Exception as e:
            logger.warning("⚠️  Bloom filter file corrupt (%s). Rebuilding.", e)

    if dataset is None:
        raise RuntimeError("No bloom filter on disk and no dataset provided to build one.")

    logger.info("🔨 Building MultiLevelBloomFilter from dataset …")
    mlbf = MultiLevelBloomFilter()
    for _, row in dataset.iterrows():
        for col in dataset.columns:
            mlbf.add(col, row[col])
    mlbf.save(path)
    return mlbf
