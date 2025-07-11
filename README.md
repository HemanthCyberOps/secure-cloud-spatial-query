# 🔐 Secure Cloud Data Storage with Spatial Query Capabilities for Encrypted Information

This project implements a **secure query processing system** for healthcare data stored in the cloud. It allows users to perform spatial and statistical queries (like Exact Match, KNN, and Range) on encrypted data using **Paillier Homomorphic Encryption** and **Multi-level Bloom Filters**.

> Built using Flask microservices, Redis for token management, and Docker for containerization.

---

## 🚀 Features

- 🔐 **Homomorphic Encryption (Paillier)** for secure computation
- 🧐 **Multi-Level Bloom Filter (HFil)** for fast encrypted query processing
- 📍 **Spatial KNN, Range, and Exact Match Queries**
- 🔑 **Token-based Authentication & Access Control** (via Redis)
- ☁️ **Dockerized Microservices** (Server 0, 1, 2)
- 🧪 Includes sample dataset and encrypted Bloom filter

---

## 📊 System Architecture

```
User → Server 0 (Token, Encryption)
     → Server 1 (Query Processing: Exact/Range/KNN)
     → Server 2 (Decryption & Homomorphic Math)
     → Redis (for token validation)
```

---

## ⚙️ Tech Stack

- Python 3.10+
- Flask (REST APIs)
- Redis (Local / Azure)
- NumPy, Pandas, `phe` (Python Paillier)
- Docker & Docker Compose
- Azure App Services (optional deployment target)

---

## 🗂️ Folder Structure

```
secure-cloud-spatial-query/
├── backend/
│   ├── server_0/          # Encryption, token generation
│   ├── server_1/          # Query processing (KNN, Range, Exact Match)
│   ├── server_2/          # Homomorphic decryption
│   ├── shared/            # Common logic (encryption, Bloom, token mgmt)
│   └── dataset/           # Healthcare CSV data
├── deployment/k8s/        # K8s YAMLs (optional)
├── test/                  # Test files
├── bloom_filter.pkl       # Stored Bloom filter state
├── requirements.txt
├── docker-compose.yml
├── .gitignore
└── README.md
```

---

## 🐳 Run with Docker Compose

```bash
docker-compose up --build
```

> This will automatically build and run:  
> - Redis container  
> - Server 0 (Port 5000)  
> - Server 1 (Port 5001)  
> - Server 2 (Port 5002)

---

## 🦪 Run Locally Without Docker

```bash
# Run Redis (locally)
redis-server

# In 3 separate terminals or tabs:
python backend/server_0/server_0.py
python backend/server_1/server_1.py
python backend/server_2/server_2.py
```

---

## 🔗 Key Endpoints

| Server | Endpoint | Method | Description |
|--------|----------|--------|-------------|
| server_0 | `/generate_token` | POST | Generates access token |
| server_0 | `/generate_query_token` | POST | Generates temporary query token |
| server_1 | `/exact_match` | POST | Query on encrypted data using Bloom Filter |
| server_1 | `/range_query` | POST | Decrypted secure billing range query |
| server_1 | `/knn_query` | POST | Location-based KNN over encrypted points |
| server_2 | `/decrypt_sum` | POST | Homomorphic sum decryption |
| server_2 | `/homomorphic_operations` | POST | Addition / Multiplication on encrypted inputs |

---

## 🧾 Example Query Token Flow

1. Generate access token → `POST /generate_token`
2. Generate query token → `POST /generate_query_token`  
3. Use both tokens to query:
   ```http
   POST /exact_match
   Headers:
     Authorization: <access_token>
     Query-Token: <query_token>
   Body:
     {
       "field": "name",
       "value": "john"
     }
   ```

---

## 📊 Dataset

The system uses a reduced and anonymized healthcare dataset:
- Fields: `name`, `billing_amount`, `latitude`, `longitude`, etc.
- Encrypted using Paillier and stored in-memory.

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

## 🙌 Acknowledgments

Built by [@HemanthCyberOps](https://github.com/HemanthCyberOps)  
Inspired by real-world encrypted data search models and academic research in secure cloud computing.

