import pandas as pd
import os
import sys
from phe.util import invert
import numpy as np
from flask import Flask, request, jsonify
import requests
import redis
import platform
import logging
import socket

# Add backend to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# ✅ Detect Local or Cloud Environment
try:
    socket.gethostbyname("securestorage-redis.redis.cache.windows.net")
    IS_CLOUD = True
except socket.gaierror:
    IS_CLOUD = False
    
# ✅ Configure Redis Connection
redis_client = redis.Redis(
    host="localhost" if not IS_CLOUD else "securestorage-redis.redis.cache.windows.net",
    port=6379 if not IS_CLOUD else 6380,
    decode_responses=True,
    password=os.getenv("REDIS_PASSWORD") if IS_CLOUD else None,
    ssl=IS_CLOUD
)

# ✅ Import Required Modules
from shared.paillier import encrypt_data, decrypt_data, homomorphic_addition, homomorphic_multiplication, public_key, EncryptedNumber, private_key
from shared.token_manager import TokenManager
from shared.BloomFilter import MultiLevelBloomFilter

app = Flask(__name__)

# ✅ Dataset Path Handling
if platform.system() == "Windows":
    dataset_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../dataset/reduced_healthcare_dataset.csv"))
else:
    dataset_path = "/app/dataset/reduced_healthcare_dataset.csv"

if not os.path.exists(dataset_path):
    raise FileNotFoundError(f"Dataset not found at path: {dataset_path}")

# ✅ Load Dataset
data_store = pd.read_csv(dataset_path)
data_store["billing_amount_encrypted"] = encrypt_data(data_store["billing_amount"].fillna(0).tolist())

# ✅ Initialize Token Manager & Bloom Filter
token_manager = TokenManager()
bloom_filter = MultiLevelBloomFilter()

for _, row in data_store.iterrows():
    bloom_filter.add("name", row["name"])

# ✅ Server 2 URL for Decryption
SERVER_2_URL = os.getenv("SERVER_2_URL")

@app.before_request
def require_authorization():
    """Require valid tokens for all queries except token generation."""
    if request.endpoint not in ['generate_token', 'generate_query_token']:
        token = request.headers.get("Authorization")
        if not token or not token_manager.validate_access_token(token):
            return jsonify({"error": "Unauthorized access"}), 401

@app.route('/exact_match', methods=['POST'])
def exact_match():
    """Secure Exact Match Query using Bloom Filter."""
    access_token = request.headers.get("Authorization")
    query_token = request.headers.get("Query-Token")

    # ✅ Log received tokens for debugging
    logging.info(f"Received Access Token: {access_token}")
    logging.info(f"Received Query Token: {query_token}")

    if not token_manager.validate_query_token(access_token, query_token):
        logging.error("❌ Query Token Validation Failed!")
        return jsonify({"error": "Unauthorized query"}), 401

    request_data = request.get_json()
    field, value = request_data.get('field'), request_data.get('value')

    if not field or not value:
        return jsonify({"error": "Field and value are required"}), 400

    value = str(value).strip().lower()

    if not bloom_filter.lookup(field, value):
        return jsonify({"error": f"No exact match found for {value}"}), 404

    results = data_store.dropna(subset=[field])
    results = results[results[field].astype(str).str.lower().str.strip() == value]

    selected_fields = ["name", "medical_condition", "insurance_provider", "gender"]
    results = results[selected_fields].drop_duplicates().dropna()

    if results.empty:
        return jsonify({"message": f"No exact match found for {value}"}), 404

    return jsonify({"results": results.to_dict(orient="records")}), 200

# ✅ Range Query API
@app.route('/range_query', methods=['POST'])
def range_query():
    access_token = request.headers.get("Authorization")
    query_token = request.headers.get("Query-Token")
    
    if not token_manager.validate_query_token(access_token, query_token):
        return jsonify({"error": "Unauthorized query"}), 401

    request_data = request.get_json()
    field, min_val, max_val = request_data.get('field'), request_data.get('min_value'), request_data.get('max_value')

    if not field or min_val is None or max_val is None:
        return jsonify({"error": "Field, min, and max values required"}), 400

    if not bloom_filter.lookup(field, str(min_val)) and not bloom_filter.lookup(field, str(max_val)):
        return jsonify({"error": "No values found in Bloom Filter for the given range"}), 404

    encrypted_values = data_store["billing_amount_encrypted"].tolist()
    decrypted_values = np.array([decrypt_data(enc) for enc in encrypted_values])

    mask = (decrypted_values >= min_val) & (decrypted_values <= max_val)
    results = data_store[mask]

    selected_fields = ["name", "medical_condition", "insurance_provider", "gender"]
    results = results[selected_fields].drop_duplicates().dropna()

    return jsonify({"results": results.to_dict(orient="records")}), 200

# ✅ KNN Query API
@app.route('/knn_query', methods=['POST'])
def knn_query():
    access_token = request.headers.get("Authorization")
    query_token = request.headers.get("Query-Token")
    
    if not token_manager.validate_query_token(access_token, query_token):
        return jsonify({"error": "Unauthorized query"}), 401

    request_data = request.get_json()
    latitude, longitude, k = request_data.get('latitude'), request_data.get('longitude'), request_data.get('k', 5)

    data_store["distance"] = ((data_store["latitude"] - latitude) ** 2 + (data_store["longitude"] - longitude) ** 2) ** 0.5
    results = data_store.nsmallest(k, "distance")
    
    selected_fields = ["name", "medical_condition", "insurance_provider", "gender"]
    results = results[selected_fields].drop_duplicates().dropna()
    
    return jsonify({"results": results.to_dict(orient="records")}), 200

# ✅ Decrypt Sum API
@app.route('/decrypt_sum', methods=['POST'])
def decrypt_sum():
    """Forward encrypted sum to Server 2 for decryption."""
    try:
        data = request.json
        encrypted_sum = data.get("encrypted_sum")

        if not encrypted_sum:
            return jsonify({"error": "Missing encrypted_sum"}), 400

        response = requests.post(f"{SERVER_2_URL}/decrypt_sum", json={"encrypted_sum": encrypted_sum})

        return jsonify(response.json()), response.status_code

    except Exception as e:
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500

if __name__ == "__main__":
    SERVER_1_PORT = int(os.getenv("SERVER_1_PORT", 5001))  # Default to 5001 if not set
    print(f"[INFO] Server 1 is running on port {SERVER_1_PORT}...")
    app.run(host="0.0.0.0", port=SERVER_1_PORT, debug=True)
