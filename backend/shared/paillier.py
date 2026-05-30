"""
Paillier Homomorphic Encryption helpers.

Keys are generated ONCE and persisted to disk (keys/ directory).
Every server loads the same keypair so encryption and decryption
always use matching keys — even across restarts.
"""
import os
import pickle
import logging
import sys
from pathlib import Path
from phe import paillier, EncryptedNumber

# Allow running this file directly for key generation
sys.path.append(str(Path(__file__).resolve().parents[1]))
from config.settings import PUBLIC_KEY_PATH, PRIVATE_KEY_PATH

logger = logging.getLogger(__name__)

# ── Key size ───────────────────────────────────────────────────────────────────
KEY_SIZE = 1024          # 1024-bit is fine for a project / demo
SCALING_FACTOR = 100     # Multiply floats by this before encrypting (int-only)


# ── Key persistence ────────────────────────────────────────────────────────────

def _save_keys(pub_key, priv_key) -> None:
    PUBLIC_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(PUBLIC_KEY_PATH, "wb") as f:
        pickle.dump(pub_key, f)
    with open(PRIVATE_KEY_PATH, "wb") as f:
        pickle.dump(priv_key, f)
    logger.info("✅ Paillier keypair saved to %s", PUBLIC_KEY_PATH.parent)


def _load_keys():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        pub_key = pickle.load(f)
    with open(PRIVATE_KEY_PATH, "rb") as f:
        priv_key = pickle.load(f)
    logger.info("✅ Paillier keypair loaded from disk.")
    return pub_key, priv_key


def _get_or_create_keys():
    if PUBLIC_KEY_PATH.exists() and PRIVATE_KEY_PATH.exists():
        try:
            return _load_keys()
        except Exception as e:
            logger.warning("⚠️  Could not load keys (%s). Regenerating.", e)

    logger.info("🔑 Generating new Paillier keypair (n_length=%d) …", KEY_SIZE)
    pub_key, priv_key = paillier.generate_paillier_keypair(n_length=KEY_SIZE)
    _save_keys(pub_key, priv_key)
    return pub_key, priv_key


# Module-level keypair — loaded once per process
public_key, private_key = _get_or_create_keys()


# ── Encryption helpers ─────────────────────────────────────────────────────────

def encrypt_value(value: float) -> EncryptedNumber:
    """Encrypt a single numeric value (scales to int first)."""
    return public_key.encrypt(int(round(float(value) * SCALING_FACTOR)))


def decrypt_value(enc_num: EncryptedNumber) -> float:
    """Decrypt a single EncryptedNumber and return the original float."""
    raw = private_key.decrypt(enc_num)
    return raw / SCALING_FACTOR


def encrypt_data(data):
    """Encrypt a list of values or a single value."""
    if isinstance(data, list):
        return [encrypt_value(v) for v in data]
    return encrypt_value(data)


def decrypt_data(encrypted_data):
    """Decrypt a list of EncryptedNumbers or a single one."""
    if isinstance(encrypted_data, list):
        return [decrypt_value(v) for v in encrypted_data]
    return decrypt_value(encrypted_data)


# ── Homomorphic operations ─────────────────────────────────────────────────────

def homomorphic_addition(*enc_nums: EncryptedNumber) -> EncryptedNumber:
    """
    Add two or more EncryptedNumbers using the phe library's built-in
    operator — this is the correct way to do Paillier addition.
    """
    if not enc_nums:
        raise ValueError("At least one EncryptedNumber is required.")
    result = enc_nums[0]
    for enc in enc_nums[1:]:
        result = result + enc          # phe handles the math correctly
    return result


def homomorphic_multiplication(enc_num: EncryptedNumber, scalar) -> EncryptedNumber:
    """Multiply an EncryptedNumber by a plaintext scalar."""
    if not isinstance(enc_num, EncryptedNumber):
        raise TypeError("First argument must be an EncryptedNumber.")
    if not isinstance(scalar, (int, float)):
        raise TypeError("Scalar must be int or float.")
    return enc_num * scalar


def serialize_encrypted(enc_num: EncryptedNumber) -> dict:
    """
    Convert an EncryptedNumber to a JSON-serialisable dict so it can be
    sent between servers over HTTP.
    """
    return {
        "ciphertext": str(enc_num.ciphertext()),
        "exponent": enc_num.exponent,
    }


def deserialize_encrypted(data: dict) -> EncryptedNumber:
    """Reconstruct an EncryptedNumber from the dict produced by serialize_encrypted."""
    return EncryptedNumber(public_key, int(data["ciphertext"]), int(data["exponent"]))
