"""
Server 1 — Query Engine
Responsibilities:
  • Exact Match query  (via Bloom filter + plaintext confirmation)
  • Range query        (on encrypted billing_amount, decrypted in-process)
  • KNN query          (Euclidean distance on lat/lon — plaintext coords)
  • Homomorphic sum    (forwards encrypted sum to Server 2 for decryption)

All query endpoints require both an access token AND a query token.
"""
import os
import sys
import logging
import requests
from pathlib import Path

import numpy as np
import pandas as pd
from flask import Flask, jsonify, request
from flask_cors import CORS

# ── Path setup ─────────────────────────────────────────────────────────────────
sys.path.append(str(Path(__file__).resolve().parents[1]))

from config.settings import DATASET_PATH, BLOOM_FILTER_PATH, SERVER_1_PORT, SERVER_2_URL
from shared.token_manager import TokenManager
from shared.BloomFilter import load_or_create_bloom_filter
from shared.paillier import (
    encrypt_data, decrypt_data,
    homomorphic_addition, serialize_encrypted,
)

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("server_1")

# ── Flask app ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ── Dataset ────────────────────────────────────────────────────────────────────
if not Path(DATASET_PATH).exists():
    raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

data_store = pd.read_csv(DATASET_PATH)
logger.info("✅ Dataset loaded (%d rows).", len(data_store))

# Pre-encrypt billing_amount column and keep alongside the DataFrame
data_store["billing_amount_encrypted"] = encrypt_data(
    data_store["billing_amount"].fillna(0).tolist()
)
logger.info("✅ billing_amount column encrypted in memory.")

# ── Bloom filter ───────────────────────────────────────────────────────────────
bloom_filter = load_or_create_bloom_filter(BLOOM_FILTER_PATH, data_store)

# ── Safe fields returned to callers ───────────────────────────────────────────
SAFE_FIELDS = ["name", "medical_condition", "insurance_provider", "gender"]


# ── Auth helper ────────────────────────────────────────────────────────────────

def _validate_tokens():
    """
    Validate both Authorization and Query-Token headers.
    Returns (access_token, query_token) on success, or raises a tuple
    (response, status_code) that the caller should return immediately.
    """
    access_token = request.headers.get("Authorization", "").strip()
    query_token  = request.headers.get("Query-Token", "").strip()

    if not access_token:
        raise _AuthError("Missing Authorization header.", 401)
    if not query_token:
        raise _AuthError("Missing Query-Token header.", 401)
    if not token_manager.validate_query_token(access_token, query_token):
        raise _AuthError("Invalid or expired tokens.", 401)

    return access_token, query_token


class _AuthError(Exception):
    def __init__(self, message, status):
        super().__init__(message)
        self.status = status


def _auth_guard(fn):
    """Decorator that wraps a route with dual-token validation."""
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            _validate_tokens()
        except _AuthError as e:
            return jsonify({"error": str(e)}), e.status
        return fn(*args, **kwargs)

    return wrapper


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "running", "server": "server_1"}), 200


# ── Exact Match ────────────────────────────────────────────────────────────────

@app.route("/exact_match", methods=["POST"])
@_auth_guard
def exact_match():
    """
    Exact match query using the Multi-Level Bloom Filter.

    Body (JSON):
        { "field": "name", "value": "bobby jackson" }

    The Bloom filter gives a fast probabilistic answer; we then confirm
    against the actual dataset to eliminate false positives.
    """
    body = request.get_json(silent=True) or {}
    field = str(body.get("field", "")).strip().lower()
    value = str(body.get("value", "")).strip().lower()

    if not field or not value:
        return jsonify({"error": "Both 'field' and 'value' are required."}), 400

    if field not in data_store.columns:
        return jsonify({"error": f"Unknown field: '{field}'."}), 400

    # ── Step 1: Bloom filter check (fast path) ─────────────────────────────────
    if not bloom_filter.lookup(field, value):
        return jsonify({"message": f"No match found for {field}='{value}' (Bloom filter)."}), 404

    # ── Step 2: Exact confirmation against dataset ─────────────────────────────
    col = data_store[field].astype(str).str.lower().str.strip()
    matches = data_store[col == value]

    available = [c for c in SAFE_FIELDS if c in matches.columns]
    results = matches[available].drop_duplicates().dropna()

    if results.empty:
        return jsonify({"message": f"No exact match found for {field}='{value}'."}), 404

    return jsonify({"results": results.to_dict(orient="records")}), 200


# ── Range Query ────────────────────────────────────────────────────────────────

@app.route("/range_query", methods=["POST"])
@_auth_guard
def range_query():
    """
    Range query on billing_amount using Paillier-encrypted values.

    The encrypted column is decrypted in-process (Server 1 holds the
    shared keypair) and filtered by [min_value, max_value].

    Body (JSON):
        { "min_value": 100, "max_value": 5000 }
    """
    body = request.get_json(silent=True) or {}

    try:
        min_val = float(body["min_value"])
        max_val = float(body["max_value"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "Numeric 'min_value' and 'max_value' are required."}), 400

    if min_val > max_val:
        return jsonify({"error": "'min_value' must be ≤ 'max_value'."}), 400

    # Decrypt the pre-encrypted billing column
    decrypted_amounts = np.array(
        [decrypt_data(enc) for enc in data_store["billing_amount_encrypted"]]
    )

    mask = (decrypted_amounts >= min_val) & (decrypted_amounts <= max_val)
    matches = data_store[mask]

    available = [c for c in SAFE_FIELDS if c in matches.columns]
    results = matches[available].drop_duplicates().dropna()

    if results.empty:
        return jsonify({"message": f"No records found in billing range [{min_val}, {max_val}]."}), 404

    return jsonify({
        "range": {"min": min_val, "max": max_val},
        "count": len(results),
        "results": results.to_dict(orient="records"),
    }), 200


# ── KNN Query ──────────────────────────────────────────────────────────────────

@app.route("/knn_query", methods=["POST"])
@_auth_guard
def knn_query():
    """
    K-Nearest Neighbours query based on geographic coordinates.

    Body (JSON):
        { "latitude": 12.34, "longitude": 56.78, "k": 5 }

    Returns the k closest records by Euclidean distance on (lat, lon).
    """
    body = request.get_json(silent=True) or {}

    try:
        lat = float(body["latitude"])
        lon = float(body["longitude"])
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "Numeric 'latitude' and 'longitude' are required."}), 400

    k = int(body.get("k", 5))
    if k < 1:
        return jsonify({"error": "'k' must be a positive integer."}), 400

    if "latitude" not in data_store.columns or "longitude" not in data_store.columns:
        return jsonify({"error": "Dataset does not contain latitude/longitude columns."}), 500

    # Euclidean distance (good enough for small geographic areas)
    df = data_store.copy()
    df["_distance"] = np.sqrt(
        (df["latitude"] - lat) ** 2 + (df["longitude"] - lon) ** 2
    )
    nearest = df.nsmallest(k, "_distance")

    available = [c for c in SAFE_FIELDS if c in nearest.columns]
    results = nearest[available].drop_duplicates().dropna()

    return jsonify({
        "query": {"latitude": lat, "longitude": lon, "k": k},
        "count": len(results),
        "results": results.to_dict(orient="records"),
    }), 200


# ── Homomorphic Sum ────────────────────────────────────────────────────────────

@app.route("/homomorphic_sum", methods=["POST"])
@_auth_guard
def homomorphic_sum():
    """
    Compute the homomorphic sum of all encrypted billing_amount values
    and forward the ciphertext to Server 2 for decryption.

    Returns the decrypted total from Server 2.
    """
    encrypted_values = data_store["billing_amount_encrypted"].tolist()

    if not encrypted_values:
        return jsonify({"error": "No encrypted data available."}), 500

    # Homomorphic addition — never decrypts here
    enc_sum = homomorphic_addition(*encrypted_values)
    serialized = serialize_encrypted(enc_sum)

    # Forward to Server 2
    try:
        resp = requests.post(
            f"{SERVER_2_URL}/decrypt_sum",
            json={"encrypted_sum": serialized},
            timeout=10,
        )
        resp.raise_for_status()
        return jsonify(resp.json()), resp.status_code
    except requests.exceptions.ConnectionError:
        return jsonify({"error": f"Cannot reach Server 2 at {SERVER_2_URL}."}), 503
    except requests.exceptions.Timeout:
        return jsonify({"error": "Server 2 timed out."}), 504
    except Exception as exc:
        logger.exception("Unexpected error calling Server 2")
        return jsonify({"error": str(exc)}), 500


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("🚀 Server 1 starting on port %d …", SERVER_1_PORT)
    app.run(host="0.0.0.0", port=SERVER_1_PORT, debug=False)
