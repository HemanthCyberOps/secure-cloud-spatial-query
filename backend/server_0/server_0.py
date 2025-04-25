import os
import logging
import platform
import sys
import numpy as np
import pandas as pd
import pickle
import redis
from flask import Flask, jsonify, request

# Add the backend directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from shared.BloomFilter import BloomFilter
from shared.token_manager import TokenManager

# ✅ Logging Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ✅ Set IS_CLOUD to False since you're using local Redis
IS_CLOUD = False

# ✅ Redis Configuration (Always connect to local Redis)
REDIS_HOST = "localhost" if not IS_CLOUD else "securestorage-redis.redis.cache.windows.net"
REDIS_PORT = 6379 if not IS_CLOUD else 6380
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD")
USE_SSL = IS_CLOUD  # Only enable SSL for Azure Redis

# ✅ Redis Connection Logic for local Redis
try:
    logging.info(f"🚀 Connecting to Redis at {REDIS_HOST}:{REDIS_PORT}")
    r = redis.StrictRedis(
        host=REDIS_HOST,
        port=REDIS_PORT,
        password=REDIS_PASSWORD,
        decode_responses=True,
        ssl=USE_SSL
    )
    r.ping()  # Test connection
    logging.info("✅ Redis Connection Successful!")
except redis.ConnectionError as e:
    logging.error(f"❌ Redis Connection Failed: {e}")
    r = None

# ✅ Flask App Setup
app = Flask(__name__)
token_manager = TokenManager()

# ✅ Dataset Path Handling
if platform.system() == "Windows":
    DATASET_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "../dataset/reduced_healthcare_dataset.csv"))
else:
    DATASET_PATH = "/app/dataset/reduced_healthcare_dataset.csv"

BLOOM_FILTER_PATH = "/home/site/wwwroot/bloom_filter.pkl"

data_store = None

# ✅ Load dataset if available
if os.path.exists(DATASET_PATH):
    try:
        data_store = pd.read_csv(DATASET_PATH)
        logging.info("✅ Dataset loaded successfully.")
    except Exception as e:
        logging.error(f"❌ Error loading dataset: {e}")
        data_store = pd.DataFrame()
else:
    logging.warning(f"⚠️ Dataset not found at {DATASET_PATH}. Initializing an empty DataFrame.")
    data_store = pd.DataFrame(columns=[
        "name", "age", "gender", "blood_type", "medical_condition",
        "date_of_admission", "doctor", "hospital", "insurance_provider",
        "billing_amount", "room_number", "admission_type",
        "discharge_date", "medication", "test_results", "latitude", "longitude"
    ])

# ✅ Bloom Filter Setup
bloom_filter_path = "bloom_filter.pkl"

def save_bloom_filter():
    """Save the Bloom filter."""
    try:
        with open(bloom_filter_path, "wb") as f:
            pickle.dump({
                "dimensions": bloom_filter.dimensions,
                "bit_array": bloom_filter.bit_array.tolist(),
                "num_hashes": bloom_filter.num_hashes
            }, f)
        logging.info("✅ Bloom filter saved successfully.")
    except Exception as e:
        logging.error(f"❌ Error saving Bloom filter: {e}")

if os.path.exists(bloom_filter_path):
    try:
        with open(bloom_filter_path, "rb") as f:
            bloom_data = pickle.load(f)
            bloom_filter = BloomFilter(dimensions=bloom_data["dimensions"], num_hashes=bloom_data["num_hashes"])
            bloom_filter.bit_array = np.array(bloom_data["bit_array"], dtype=bool)
        logging.info("✅ Bloom filter loaded successfully.")
    except (EOFError, pickle.UnpicklingError, KeyError, TypeError) as e:
        logging.error(f"⚠️ Bloom filter file is corrupted: {e}. Initializing a new one.")
        bloom_filter = BloomFilter()
        save_bloom_filter()
else:
    logging.warning("⚠️ No Bloom filter file found. Initializing a new one.")
    bloom_filter = BloomFilter()
    save_bloom_filter()

# ✅ Health Check API
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "running"}), 200

@app.route("/cache_test", methods=["GET"])
def cache_test():
    try:
        if not r:
            raise redis.ConnectionError("Redis connection not established.")
        
        # Debugging connection status
        logging.info(f"Redis Host: {REDIS_HOST}, Port: {REDIS_PORT}, SSL: {r.connection_pool.connection_kwargs.get('ssl', False)}")
        
        test_key = "test_key"
        test_value = "Redis connection successful"
        r.set(test_key, test_value)
        return jsonify({"message": "✅ Data stored in Redis!", "data": r.get(test_key)}), 200
    except redis.ConnectionError as ce:
        logging.error(f"❌ Redis Connection Error: {ce}")
        return jsonify({"error": "Redis is not connected! Please check Redis server."}), 500
    except Exception as e:
        logging.error(f"❌ Redis Error: {e}")
        return jsonify({"error": "Internal Server Error"}), 500


# ✅ Generate Token API
@app.route('/generate_token', methods=['POST'])
def generate_token():
    user_id = request.json.get('user_id')
    if not user_id:
        return jsonify({"error": "❌ Missing 'user_id'"}), 400
    token = token_manager.generate_access_token(user_id)
    return jsonify({"token": token}), 200

@app.route('/generate_query_token', methods=['POST'])
def generate_query_token():
    access_token = request.headers.get("Authorization")
    
    if not access_token:
        return jsonify({"error": "❌ Missing Authorization header"}), 400

    if not token_manager.validate_access_token(access_token):
        return jsonify({"error": "❌ Invalid or expired access token"}), 401

    # ✅ Log the raw request data
    request_data = request.get_json(silent=True)
    if request_data is None:
        return jsonify({"error": "❌ Invalid JSON. Ensure request body is formatted correctly."}), 400

    query = request_data.get("query")
    if not query:
        return jsonify({"error": "❌ 'query' field is required"}), 400

    logging.info(f"✅ Query Received: {query}")

    query_token = token_manager.generate_query_token(access_token, query)
    return jsonify({"query_token": query_token}), 200


# ✅ Add Data API
@app.route('/add_data', methods=['POST'])
def add_data():
    token = request.headers.get("Authorization")
    if not token or not token_manager.validate_access_token(token):
        return jsonify({"error": "Unauthorized access"}), 401

    new_data = request.json
    if not new_data:
        return jsonify({"error": "Invalid or missing data"}), 400

    try:
        if "name" not in new_data:
            return jsonify({"error": "Missing required field: 'name'"}), 400

        bloom_filter.add("name", new_data["name"])
        save_bloom_filter()

        global data_store
        new_row = pd.DataFrame([new_data])
        data_store = pd.concat([data_store, new_row], ignore_index=True)
        data_store.to_csv(DATASET_PATH, index=False)

        return jsonify({"status": "Data added successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ✅ View Data API
@app.route('/view_data', methods=['GET'])
def view_data():
    token = request.headers.get("Authorization")
    if not token or not token_manager.validate_access_token(token):
        return jsonify({"error": "Unauthorized access"}), 401
    return jsonify(data_store.to_dict(orient="records")), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 80))  # Default to 80 for Azure
    app.run(host="0.0.0.0", port=port, debug=True)
