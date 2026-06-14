"""
End-to-end tests for all three servers.

Run with:
    pytest test/test_endpoints.py -v

Servers must be running locally before executing these tests:
    python backend/server_0/server_0.py
    python backend/server_1/server_1.py
    python backend/server_2/server_2.py
"""
import pytest
import requests

BASE_0 = "http://127.0.0.1:5000"
BASE_1 = "http://127.0.0.1:5001"
BASE_2 = "http://127.0.0.1:5002"

# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def access_token():
    """Generate a real access token from Server 0 once per test session."""
    resp = requests.post(f"{BASE_0}/generate_token", json={"user_id": "test_user"})
    assert resp.status_code == 200, f"Token generation failed: {resp.text}"
    token = resp.json().get("access_token")
    assert token, "No access_token in response"
    return token


@pytest.fixture(scope="session")
def query_token(access_token):
    """Generate a real query token from Server 0 once per test session."""
    resp = requests.post(
        f"{BASE_0}/generate_query_token",
        headers={"Authorization": access_token},
        json={"query": "test_query"},
    )
    assert resp.status_code == 200, f"Query token generation failed: {resp.text}"
    token = resp.json().get("query_token")
    assert token, "No query_token in response"
    return token


# ── Server 0 tests ─────────────────────────────────────────────────────────────

class TestServer0:

    def test_health(self):
        resp = requests.get(f"{BASE_0}/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "running"

    def test_generate_token_missing_user_id(self):
        resp = requests.post(f"{BASE_0}/generate_token", json={})
        assert resp.status_code == 400

    def test_generate_token_success(self, access_token):
        # access_token fixture already validated this; just confirm it's a hex string
        assert len(access_token) == 64

    def test_generate_query_token_no_auth(self):
        resp = requests.post(
            f"{BASE_0}/generate_query_token",
            json={"query": "exact_match"},
        )
        assert resp.status_code == 401

    def test_generate_query_token_success(self, query_token):
        assert len(query_token) == 64

    def test_view_data_unauthorized(self):
        resp = requests.get(f"{BASE_0}/view_data")
        assert resp.status_code == 401

    def test_view_data_authorized(self, access_token):
        resp = requests.get(
            f"{BASE_0}/view_data",
            headers={"Authorization": access_token},
        )
        assert resp.status_code == 200
        assert "records" in resp.json()

    def test_add_data_missing_name(self, access_token):
        resp = requests.post(
            f"{BASE_0}/add_data",
            headers={"Authorization": access_token},
            json={"age": 30},
        )
        assert resp.status_code == 400

    def test_add_data_success(self, access_token):
        record = {
            "name": "Test Patient",
            "age": 25,
            "gender": "Male",
            "blood_type": "O+",
            "medical_condition": "Flu",
            "billing_amount": 500.0,
            "latitude": 10.0,
            "longitude": 20.0,
        }
        resp = requests.post(
            f"{BASE_0}/add_data",
            headers={"Authorization": access_token},
            json=record,
        )
        assert resp.status_code == 201


# ── Server 1 tests ─────────────────────────────────────────────────────────────

class TestServer1:

    def test_health(self):
        resp = requests.get(f"{BASE_1}/health")
        assert resp.status_code == 200

    def test_exact_match_no_tokens(self):
        resp = requests.post(
            f"{BASE_1}/exact_match",
            json={"field": "name", "value": "bobby jackson"},
        )
        assert resp.status_code == 401

    def test_exact_match_found(self, access_token, query_token):
        resp = requests.post(
            f"{BASE_1}/exact_match",
            headers={"Authorization": access_token, "Query-Token": query_token},
            json={"field": "name", "value": "bobby jackson"},
        )
        # 200 if found, 404 if not in dataset — both are valid outcomes
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            assert "results" in resp.json()

    def test_exact_match_unknown_field(self, access_token, query_token):
        resp = requests.post(
            f"{BASE_1}/exact_match",
            headers={"Authorization": access_token, "Query-Token": query_token},
            json={"field": "nonexistent_field", "value": "anything"},
        )
        assert resp.status_code == 400

    def test_range_query_success(self, access_token, query_token):
        resp = requests.post(
            f"{BASE_1}/range_query",
            headers={"Authorization": access_token, "Query-Token": query_token},
            json={"min_value": 100, "max_value": 50000},
        )
        assert resp.status_code in (200, 404)
        if resp.status_code == 200:
            assert "results" in resp.json()

    def test_range_query_invalid_range(self, access_token, query_token):
        resp = requests.post(
            f"{BASE_1}/range_query",
            headers={"Authorization": access_token, "Query-Token": query_token},
            json={"min_value": 5000, "max_value": 100},
        )
        assert resp.status_code == 400

    def test_range_query_missing_params(self, access_token, query_token):
        resp = requests.post(
            f"{BASE_1}/range_query",
            headers={"Authorization": access_token, "Query-Token": query_token},
            json={"min_value": 100},
        )
        assert resp.status_code == 400

    def test_knn_query_success(self, access_token, query_token):
        resp = requests.post(
            f"{BASE_1}/knn_query",
            headers={"Authorization": access_token, "Query-Token": query_token},
            json={"latitude": 0.0, "longitude": 0.0, "k": 3},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data
        assert data["query"]["k"] == 3

    def test_knn_query_missing_coords(self, access_token, query_token):
        resp = requests.post(
            f"{BASE_1}/knn_query",
            headers={"Authorization": access_token, "Query-Token": query_token},
            json={"k": 3},
        )
        assert resp.status_code == 400

    def test_homomorphic_sum(self, access_token, query_token):
        resp = requests.post(
            f"{BASE_1}/homomorphic_sum",
            headers={"Authorization": access_token, "Query-Token": query_token},
        )
        assert resp.status_code == 200
        assert "decrypted_sum" in resp.json()


# ── Server 2 tests ─────────────────────────────────────────────────────────────

class TestServer2:

    def test_health(self):
        resp = requests.get(f"{BASE_2}/health")
        assert resp.status_code == 200

    def test_decrypt_sum_missing_body(self):
        resp = requests.post(f"{BASE_2}/decrypt_sum", json={})
        assert resp.status_code == 400

    def test_homomorphic_addition(self):
        """
        Encrypt two values locally, send their serialised form to Server 2,
        and verify the decrypted sum is correct.
        """
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from backend.shared.paillier import encrypt_value, serialize_encrypted

        a, b = 150.0, 250.0
        enc_a = serialize_encrypted(encrypt_value(a))
        enc_b = serialize_encrypted(encrypt_value(b))

        resp = requests.post(
            f"{BASE_2}/homomorphic_operations",
            json={"operation": "addition", "encrypted_values": [enc_a, enc_b]},
        )
        assert resp.status_code == 200
        result = resp.json()["decrypted_result"]
        # Allow small floating-point rounding from the scaling factor
        assert abs(result - (a + b)) < 1.0, f"Expected ~{a+b}, got {result}"

    def test_homomorphic_multiplication(self):
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from backend.shared.paillier import encrypt_value, serialize_encrypted

        value  = 200.0
        scalar = 3
        enc_v  = serialize_encrypted(encrypt_value(value))

        resp = requests.post(
            f"{BASE_2}/homomorphic_operations",
            json={
                "operation": "multiplication",
                "encrypted_values": [enc_v],
                "scalar": scalar,
            },
        )
        assert resp.status_code == 200
        result = resp.json()["decrypted_result"]
        assert abs(result - (value * scalar)) < 1.0, f"Expected ~{value*scalar}, got {result}"

    def test_homomorphic_unknown_operation(self):
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        from backend.shared.paillier import encrypt_value, serialize_encrypted

        enc_v = serialize_encrypted(encrypt_value(100.0))
        resp = requests.post(
            f"{BASE_2}/homomorphic_operations",
            json={"operation": "division", "encrypted_values": [enc_v]},
        )
        assert resp.status_code == 400
