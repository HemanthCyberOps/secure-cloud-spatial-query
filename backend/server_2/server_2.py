"""
Server 2 — Crypto Engine
Responsibilities:
  • Decrypt a homomorphic sum forwarded from Server 1
  • Decrypt arbitrary ciphertext lists
  • Perform homomorphic addition / scalar multiplication and return result
"""
import sys
import logging
from pathlib import Path

from flask import Flask, jsonify, request
from flask_cors import CORS

# ── Path setup ─────────────────────────────────────────────────────────────────
sys.path.append(str(Path(__file__).resolve().parents[1]))

from config.settings import SERVER_2_PORT
from shared.paillier import (
    public_key, private_key,
    decrypt_data, decrypt_value,
    homomorphic_addition, homomorphic_multiplication,
    serialize_encrypted, deserialize_encrypted,
    SCALING_FACTOR,
)

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("server_2")

# ── Flask app ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "running", "server": "server_2"}), 200


# ── Decrypt Sum ────────────────────────────────────────────────────────────────

@app.route("/decrypt_sum", methods=["POST"])
def decrypt_sum():
    """
    Decrypt a homomorphic sum forwarded from Server 1.

    Body (JSON):
        {
          "encrypted_sum": {
            "ciphertext": "<large int as string>",
            "exponent": <int>
          }
        }

    Response:
        { "decrypted_sum": <float> }
    """
    body = request.get_json(silent=True) or {}
    enc_data = body.get("encrypted_sum")

    if not enc_data or not isinstance(enc_data, dict):
        return jsonify({"error": "Missing or invalid 'encrypted_sum'. Expected a dict with 'ciphertext' and 'exponent'."}), 400

    try:
        enc_sum = deserialize_encrypted(enc_data)
        result  = decrypt_value(enc_sum)
        return jsonify({"decrypted_sum": result}), 200
    except Exception as exc:
        logger.exception("decrypt_sum failed")
        return jsonify({"error": f"Decryption failed: {exc}"}), 500


# ── Decrypt List ───────────────────────────────────────────────────────────────

@app.route("/decrypt", methods=["POST"])
def decrypt():
    """
    Decrypt a list of serialised EncryptedNumbers.

    Body (JSON):
        {
          "encrypted_data": [
            { "ciphertext": "...", "exponent": 0 },
            ...
          ]
        }

    Response:
        { "decrypted_values": [<float>, ...] }
    """
    body = request.get_json(silent=True) or {}
    enc_list = body.get("encrypted_data")

    if not enc_list or not isinstance(enc_list, list):
        return jsonify({"error": "Missing or invalid 'encrypted_data'. Expected a list of objects."}), 400

    try:
        results = []
        for item in enc_list:
            enc_num = deserialize_encrypted(item)
            results.append(decrypt_value(enc_num))
        return jsonify({"decrypted_values": results}), 200
    except Exception as exc:
        logger.exception("decrypt failed")
        return jsonify({"error": f"Decryption failed: {exc}"}), 500


# ── Homomorphic Operations ─────────────────────────────────────────────────────

@app.route("/homomorphic_operations", methods=["POST"])
def homomorphic_operations():
    """
    Perform homomorphic addition or scalar multiplication, then decrypt.

    Body (JSON) for addition:
        {
          "operation": "addition",
          "encrypted_values": [
            { "ciphertext": "...", "exponent": 0 },
            ...
          ]
        }

    Body (JSON) for multiplication:
        {
          "operation": "multiplication",
          "encrypted_values": [ { "ciphertext": "...", "exponent": 0 } ],
          "scalar": 3
        }

    Response:
        { "decrypted_result": <float> }
    """
    body = request.get_json(silent=True) or {}
    operation     = body.get("operation")
    enc_list      = body.get("encrypted_values")
    scalar        = body.get("scalar")

    if not enc_list or not isinstance(enc_list, list):
        return jsonify({"error": "Missing or invalid 'encrypted_values'."}), 400

    try:
        enc_numbers = [deserialize_encrypted(item) for item in enc_list]
    except Exception as exc:
        return jsonify({"error": f"Could not deserialise encrypted values: {exc}"}), 400

    try:
        if operation == "addition":
            result_enc = homomorphic_addition(*enc_numbers)

        elif operation == "multiplication":
            if scalar is None:
                return jsonify({"error": "'scalar' is required for multiplication."}), 400
            if len(enc_numbers) != 1:
                return jsonify({"error": "Multiplication expects exactly one encrypted value."}), 400
            result_enc = homomorphic_multiplication(enc_numbers[0], scalar)

        else:
            return jsonify({"error": "Unknown operation. Use 'addition' or 'multiplication'."}), 400

        decrypted = decrypt_value(result_enc)
        return jsonify({"decrypted_result": decrypted}), 200

    except Exception as exc:
        logger.exception("homomorphic_operations failed")
        return jsonify({"error": str(exc)}), 500


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("🚀 Server 2 starting on port %d …", SERVER_2_PORT)
    app.run(host="0.0.0.0", port=SERVER_2_PORT, debug=False)
