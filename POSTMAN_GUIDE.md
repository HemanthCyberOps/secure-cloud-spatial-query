# Postman Testing Guide

All servers run locally. Start them before testing:

```
python backend/server_0/server_0.py   → http://localhost:5000
python backend/server_1/server_1.py   → http://localhost:5001
python backend/server_2/server_2.py   → http://localhost:5002
```

Redis must also be running:
```
"C:\Program Files\Redis\redis-server.exe"
```

---

## Step 1 — Generate Access Token (Server 0)

**POST** `http://localhost:5000/generate_token`

Headers:
```
Content-Type: application/json
```

Body (raw JSON):
```json
{ "user_id": "alice" }
```

Response:
```json
{ "access_token": "<64-char hex>" }
```

Copy the `access_token` — you need it for every subsequent request.

---

## Step 2 — Generate Query Token (Server 0)

**POST** `http://localhost:5000/generate_query_token`

Headers:
```
Content-Type: application/json
Authorization: <your_access_token>
```

Body:
```json
{ "query": "exact_match" }
```

Response:
```json
{ "query_token": "<64-char hex>" }
```

Copy the `query_token` — it's required for all Server 1 query endpoints.
It expires in 10 minutes, so generate a new one if it expires.

---

## Step 3 — Health Checks

**GET** `http://localhost:5000/health`
**GET** `http://localhost:5001/health`
**GET** `http://localhost:5002/health`

All should return:
```json
{ "status": "running", "server": "server_X" }
```

---

## Step 4 — View Data (Server 0)

**GET** `http://localhost:5000/view_data`

Headers:
```
Authorization: <access_token>
```

Returns safe fields (name, age, gender, medical_condition, etc.) for all records.

---

## Step 5 — Add Data (Server 0)

**POST** `http://localhost:5000/add_data`

Headers:
```
Content-Type: application/json
Authorization: <access_token>
```

Body:
```json
{
  "name": "John Doe",
  "age": 35,
  "gender": "Male",
  "blood_type": "A+",
  "medical_condition": "Diabetes",
  "billing_amount": 1500.0,
  "latitude": 12.9716,
  "longitude": 77.5946
}
```

Response: `201 Created`

---

## Step 6 — Exact Match Query (Server 1)

**POST** `http://localhost:5001/exact_match`

Headers:
```
Content-Type: application/json
Authorization: <access_token>
Query-Token: <query_token>
```

Body:
```json
{ "field": "name", "value": "bobby jackson" }
```

Note: values are case-insensitive. Try names from the dataset.

Response:
```json
{
  "results": [
    {
      "name": "Bobby Jackson",
      "medical_condition": "Cancer",
      "insurance_provider": "Blue Cross",
      "gender": "Male"
    }
  ]
}
```

---

## Step 7 — Range Query on Billing Amount (Server 1)

**POST** `http://localhost:5001/range_query`

Headers:
```
Content-Type: application/json
Authorization: <access_token>
Query-Token: <query_token>
```

Body:
```json
{ "min_value": 100, "max_value": 500 }
```

This decrypts the Paillier-encrypted billing_amount column in memory
and filters by the given range. Only safe fields are returned.

---

## Step 8 — KNN Query (Server 1)

**POST** `http://localhost:5001/knn_query`

Headers:
```
Content-Type: application/json
Authorization: <access_token>
Query-Token: <query_token>
```

Body:
```json
{ "latitude": 0.0, "longitude": 0.0, "k": 3 }
```

Returns the 3 nearest patients by geographic distance.

---

## Step 9 — Homomorphic Sum (Server 1 → Server 2)

**POST** `http://localhost:5001/homomorphic_sum`

Headers:
```
Authorization: <access_token>
Query-Token: <query_token>
```

No body needed. Server 1 computes the encrypted sum of all billing amounts
and forwards the ciphertext to Server 2 for decryption.

Response:
```json
{ "decrypted_sum": 123456.78 }
```

---

## Step 10 — Direct Homomorphic Operations (Server 2)

### Addition

**POST** `http://localhost:5002/homomorphic_operations`

Body:
```json
{
  "operation": "addition",
  "encrypted_values": [
    { "ciphertext": "<int>", "exponent": 0 },
    { "ciphertext": "<int>", "exponent": 0 }
  ]
}
```

### Multiplication

```json
{
  "operation": "multiplication",
  "encrypted_values": [
    { "ciphertext": "<int>", "exponent": 0 }
  ],
  "scalar": 3
}
```

To get valid ciphertext values, use the Python helper:
```python
from backend.shared.paillier import encrypt_value, serialize_encrypted
print(serialize_encrypted(encrypt_value(250.0)))
```

---

## Token Flow Summary

```
POST /generate_token          → access_token (1 hour TTL)
POST /generate_query_token    → query_token  (10 min TTL)

All Server 1 queries need both:
  Header: Authorization: <access_token>
  Header: Query-Token:   <query_token>
```
