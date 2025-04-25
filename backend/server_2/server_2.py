from flask import Flask, request, jsonify
import os
import sys
import platform
from phe.util import invert
from phe import paillier

# Add backend directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import required cryptographic functions
from shared.paillier import safe_decrypt, public_key, private_key, EncryptedNumber, SCALING_FACTOR

app = Flask(__name__)

# ✅ Health Check API
@app.route('/health', methods=['GET'])
def health_check():
    """Check if Server 2 is running."""
    return jsonify({"status": "running"}), 200

# ✅ Decryption API
@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Decrypt data forwarded from Server 1."""
    try:
        encrypted_data = request.json.get('encrypted_data')

        if not encrypted_data or not isinstance(encrypted_data, list):
            return jsonify({"error": "Invalid or missing 'encrypted_data'. Expected a list."}), 400

        decrypted_values = []
        for ciphertext in encrypted_data:
            try:
                decrypted_value = private_key.decrypt(EncryptedNumber(public_key, int(ciphertext)))
                decrypted_values.append(decrypted_value)
            except Exception as e:
                print(f"[ERROR] Failed to decrypt value {ciphertext}: {e}")
                return jsonify({"error": f"Failed to decrypt value: {e}"}), 500

        return jsonify({"decrypted_values": decrypted_values}), 200

    except Exception as e:
        print(f"[ERROR] Decryption error: {e}")
        return jsonify({"error": str(e)}), 500

# ✅ Secure Homomorphic Sum Decryption API
@app.route('/decrypt_sum', methods=['POST'])
def decrypt_sum():
    """Safely decrypt a homomorphic sum and apply modular correction to prevent overflow."""
    try:
        data = request.json
        encrypted_sum_str = data.get("encrypted_sum")

        if not encrypted_sum_str:
            return jsonify({"error": "Missing encrypted_sum"}), 400

        try:
            # Convert encrypted sum string into integer and reconstruct EncryptedNumber
            encrypted_sum_value = int(encrypted_sum_str)
            encrypted_sum = EncryptedNumber(public_key, encrypted_sum_value)

            # Perform decryption
            decrypted_sum = private_key.decrypt(encrypted_sum)

            # Handle modular wrap-around to ensure correct values
            n = public_key.n
            if decrypted_sum > (n // 2):
                decrypted_sum -= n  # Correct modular wrap-around
            elif decrypted_sum < 0:
                decrypted_sum += n  # Ensure positivity

            # Apply scaling factor correction
            decrypted_sum *= SCALING_FACTOR  # Use same SCALING_FACTOR as in paillier.py

            return jsonify({"decrypted_sum": decrypted_sum}), 200

        except Exception as e:
            return jsonify({"error": f"Decryption failed: {str(e)}"}), 500

    except Exception as e:
        return jsonify({"error": f"Internal Server Error: {str(e)}"}), 500

# ✅ Homomorphic Operations API
@app.route('/homomorphic_operations', methods=['POST'])
def homomorphic_operations():
    """Perform homomorphic addition and scalar multiplication."""
    try:
        request_data = request.json
        operation = request_data.get("operation")
        encrypted_values = request_data.get("encrypted_values")
        scalar = request_data.get("scalar")

        if not encrypted_values or not isinstance(encrypted_values, list):
            return jsonify({"error": "Invalid or missing 'encrypted_values'. Expected a list."}), 400

        enc_numbers = []
        for val in encrypted_values:
            try:
                enc_num = EncryptedNumber(public_key, int(val))
                enc_numbers.append(enc_num)
            except Exception as e:
                print(f"[ERROR] Invalid encrypted value {val}: {e}")
                return jsonify({"error": f"Invalid encrypted value: {e}"}), 400

        if operation == "addition":
            result_enc = sum(enc_numbers)
        elif operation == "multiplication":
            if scalar is None:
                return jsonify({"error": "Missing 'scalar' for multiplication."}), 400
            result_enc = enc_numbers[0] * scalar
        else:
            return jsonify({"error": "Invalid operation. Supported: 'addition', 'multiplication' with scalar."}), 400

        decrypted_result = private_key.decrypt(result_enc)
        return jsonify({"decrypted_result": decrypted_result}), 200

    except Exception as e:
        print(f"[ERROR] Homomorphic operation error: {e}")
        return jsonify({"error": str(e)}), 500

# ✅ Server Setup for Local & Azure Deployment
if __name__ == "__main__":
    if platform.system() == "Windows":
        SERVER_2_PORT = 5002  # Default local port
    else:
        SERVER_2_PORT = int(os.getenv("SERVER_2_PORT", 5002))

    print(f"[INFO] Server 2 is running on port {SERVER_2_PORT}...")
    app.run(host="0.0.0.0", port=SERVER_2_PORT, debug=True)
