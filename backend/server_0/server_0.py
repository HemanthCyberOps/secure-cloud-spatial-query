"""
Server 0 — Gateway  (VaultQuery)
Responsibilities:
  • User authentication (access tokens)
  • Query token issuance
  • Single-record data ingestion
  • Bulk file upload  — CSV / Excel with column mapping + validation report
  • Template download
  • Read-only data view
"""
import io
import os
import sys
import uuid
import logging
from pathlib import Path

import pandas as pd
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

# ── Path setup ─────────────────────────────────────────────────────────────────
sys.path.append(str(Path(__file__).resolve().parents[1]))

from config.settings import DATASET_PATH, BLOOM_FILTER_PATH, SERVER_0_PORT
from shared.token_manager import TokenManager
from shared.BloomFilter import load_or_create_bloom_filter

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("server_0")

# ── Flask app ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})   # allow React dev server

token_manager = TokenManager()

# ── Schema ─────────────────────────────────────────────────────────────────────
REQUIRED_FIELDS = ["name", "billing_amount"]          # must be present
OPTIONAL_FIELDS = [
    "age", "gender", "blood_type", "medical_condition",
    "date_of_admission", "doctor", "hospital", "insurance_provider",
    "room_number", "admission_type", "discharge_date",
    "medication", "test_results", "latitude", "longitude",
]
ALL_FIELDS = REQUIRED_FIELDS + OPTIONAL_FIELDS

# Common aliases users might have in their own files → our field name
_ALIASES: dict[str, str] = {
    # name
    "patient_name": "name", "patientname": "name", "patient": "name",
    "full_name": "name", "fullname": "name",
    # billing_amount
    "billing": "billing_amount", "amount": "billing_amount",
    "charge": "billing_amount", "total": "billing_amount",
    "bill_amt": "billing_amount", "billamt": "billing_amount",
    "total_charge": "billing_amount",
    # age
    "patient_age": "age",
    # gender
    "sex": "gender",
    # medical_condition
    "condition": "medical_condition", "diagnosis": "medical_condition",
    "disease": "medical_condition",
    # insurance_provider
    "insurance": "insurance_provider", "insurer": "insurance_provider",
    "payer": "insurance_provider",
    # latitude / longitude
    "lat": "latitude", "gps_lat": "latitude",
    "lon": "longitude", "lng": "longitude", "gps_lon": "longitude",
    "gps_long": "longitude", "long": "longitude",
    # hospital
    "hospital_name": "hospital", "facility": "hospital",
    # doctor
    "physician": "doctor", "doctor_name": "doctor",
}

# ── In-memory upload staging (upload_id → DataFrame) ──────────────────────────
_staged: dict[str, pd.DataFrame] = {}

# ── Dataset ────────────────────────────────────────────────────────────────────
if Path(DATASET_PATH).exists():
    data_store = pd.read_csv(DATASET_PATH)
    logger.info("✅ Dataset loaded (%d rows).", len(data_store))
else:
    logger.warning("⚠️  Dataset not found at %s — starting empty.", DATASET_PATH)
    data_store = pd.DataFrame(columns=ALL_FIELDS)

# ── Bloom filter ───────────────────────────────────────────────────────────────
bloom_filter = load_or_create_bloom_filter(BLOOM_FILTER_PATH, data_store)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _auth_required():
    token = request.headers.get("Authorization", "").strip()
    if not token or not token_manager.validate_access_token(token):
        return jsonify({"error": "Unauthorized — invalid or missing access token."}), 401
    return None


def _auto_map_columns(columns: list[str]) -> dict[str, str]:
    """
    Try to automatically map a file's column names to our schema.
    Returns { file_column: our_field } for every column we can recognise.
    """
    mapping: dict[str, str] = {}
    for col in columns:
        normalised = col.strip().lower().replace(" ", "_")
        if normalised in ALL_FIELDS:
            mapping[col] = normalised
        elif normalised in _ALIASES:
            mapping[col] = _ALIASES[normalised]
    return mapping


def _read_uploaded_file(file) -> pd.DataFrame:
    """Parse an uploaded CSV or Excel file into a DataFrame."""
    filename = file.filename.lower()
    if filename.endswith(".csv"):
        return pd.read_csv(file)
    elif filename.endswith((".xlsx", ".xls")):
        return pd.read_excel(file, engine="openpyxl")
    else:
        raise ValueError(f"Unsupported file type: {file.filename}")


def _validate_and_ingest(df: pd.DataFrame, mapping: dict[str, str]):
    """
    Apply column mapping, validate each row, ingest valid rows.
    Returns a validation report dict.
    """
    global data_store, bloom_filter

    # Rename columns according to mapping
    df = df.rename(columns=mapping)

    # Drop columns we don't know about
    known = [c for c in df.columns if c in ALL_FIELDS]
    df = df[known]

    imported = 0
    skipped = 0
    errors: list[dict] = []

    new_rows: list[dict] = []

    for idx, row in df.iterrows():
        row_num = int(idx) + 2          # +2: 1-based + header row
        record = row.dropna().to_dict()

        # ── Required field check ───────────────────────────────────────────────
        missing = [f for f in REQUIRED_FIELDS if f not in record or str(record[f]).strip() == ""]
        if missing:
            errors.append({"row": row_num, "reason": f"Missing required field(s): {', '.join(missing)}"})
            skipped += 1
            continue

        # ── Type checks ────────────────────────────────────────────────────────
        try:
            record["billing_amount"] = float(record["billing_amount"])
        except (ValueError, TypeError):
            errors.append({"row": row_num, "reason": f"Invalid billing_amount: '{record['billing_amount']}'"})
            skipped += 1
            continue

        if "latitude" in record:
            try:
                lat = float(record["latitude"])
                if not (-90 <= lat <= 90):
                    raise ValueError
                record["latitude"] = lat
            except (ValueError, TypeError):
                errors.append({"row": row_num, "reason": f"Invalid latitude: '{record['latitude']}'"})
                skipped += 1
                continue

        if "longitude" in record:
            try:
                lon = float(record["longitude"])
                if not (-180 <= lon <= 180):
                    raise ValueError
                record["longitude"] = lon
            except (ValueError, TypeError):
                errors.append({"row": row_num, "reason": f"Invalid longitude: '{record['longitude']}'"})
                skipped += 1
                continue

        # ── Duplicate check ────────────────────────────────────────────────────
        name_lower = str(record["name"]).strip().lower()
        if not data_store.empty and "name" in data_store.columns:
            existing = data_store["name"].astype(str).str.lower().str.strip()
            if name_lower in existing.values:
                errors.append({"row": row_num, "reason": f"Duplicate record: '{record['name']}'"})
                skipped += 1
                continue

        # ── Normalise name ─────────────────────────────────────────────────────
        record["name"] = str(record["name"]).strip()

        new_rows.append(record)
        imported += 1

    # ── Persist valid rows ─────────────────────────────────────────────────────
    if new_rows:
        new_df = pd.DataFrame(new_rows)
        data_store = pd.concat([data_store, new_df], ignore_index=True)
        data_store.to_csv(DATASET_PATH, index=False)

        # Update Bloom filter
        for record in new_rows:
            for field, value in record.items():
                bloom_filter.add(field, value)
        bloom_filter.save(BLOOM_FILTER_PATH)

    logger.info("✅ Bulk ingest: %d imported, %d skipped.", imported, skipped)

    return {
        "total_rows": imported + skipped,
        "imported": imported,
        "skipped": skipped,
        "errors": errors[:50],          # cap at 50 error lines in response
    }


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "running", "server": "server_0", "product": "VaultQuery"}), 200


# ── Auth ───────────────────────────────────────────────────────────────────────

@app.route("/generate_token", methods=["POST"])
def generate_token():
    body = request.get_json(silent=True) or {}
    user_id = str(body.get("user_id", "")).strip()
    if not user_id:
        return jsonify({"error": "Missing 'user_id' in request body."}), 400
    token = token_manager.generate_access_token(user_id)
    return jsonify({"access_token": token}), 200


@app.route("/generate_query_token", methods=["POST"])
def generate_query_token():
    err = _auth_required()
    if err:
        return err
    access_token = request.headers.get("Authorization", "").strip()
    body = request.get_json(silent=True) or {}
    query = str(body.get("query", "")).strip()
    if not query:
        return jsonify({"error": "Missing 'query' field in request body."}), 400
    query_token = token_manager.generate_query_token(access_token, query)
    return jsonify({"query_token": query_token}), 200


# ── Single record ──────────────────────────────────────────────────────────────

@app.route("/add_data", methods=["POST"])
def add_data():
    err = _auth_required()
    if err:
        return err

    new_record = request.get_json(silent=True)
    if not new_record or not isinstance(new_record, dict):
        return jsonify({"error": "Request body must be a JSON object."}), 400
    if "name" not in new_record:
        return jsonify({"error": "Missing required field: 'name'."}), 400

    global data_store
    for field, value in new_record.items():
        bloom_filter.add(field, value)
    bloom_filter.save(BLOOM_FILTER_PATH)

    new_row = pd.DataFrame([new_record])
    data_store = pd.concat([data_store, new_row], ignore_index=True)
    data_store.to_csv(DATASET_PATH, index=False)

    logger.info("✅ Single record added: %s", new_record.get("name"))
    return jsonify({"status": "Record added successfully."}), 201


@app.route("/view_data", methods=["GET"])
def view_data():
    err = _auth_required()
    if err:
        return err
    safe_fields = ["name", "age", "gender", "medical_condition",
                   "insurance_provider", "admission_type"]
    available = [c for c in safe_fields if c in data_store.columns]
    return jsonify({"records": data_store[available].to_dict(orient="records")}), 200


# ── File upload — Step 1: preview + auto-mapping ───────────────────────────────

@app.route("/upload/preview", methods=["POST"])
def upload_preview():
    """
    Step 1 of bulk upload.
    Accept a CSV or Excel file, return:
      - first 5 rows as preview
      - detected column names
      - auto-suggested column mapping
      - a staging upload_id for step 2

    Headers:  Authorization: <access_token>
    Body:     multipart/form-data  file=<file>
    """
    err = _auth_required()
    if err:
        return err

    if "file" not in request.files:
        return jsonify({"error": "No file provided. Use multipart/form-data with key 'file'."}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Empty filename."}), 400

    try:
        df = _read_uploaded_file(file)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Could not parse file: {e}"}), 400

    if df.empty:
        return jsonify({"error": "File is empty."}), 400

    # Stage the dataframe in memory
    upload_id = str(uuid.uuid4())
    _staged[upload_id] = df

    columns = df.columns.tolist()
    auto_mapping = _auto_map_columns(columns)

    # Preview: first 5 rows, NaN → None for JSON
    preview = df.head(5).where(pd.notnull(df), None).to_dict(orient="records")

    return jsonify({
        "upload_id": upload_id,
        "filename": file.filename,
        "total_rows": len(df),
        "columns": columns,
        "auto_mapping": auto_mapping,       # { file_col: our_field }
        "our_fields": ALL_FIELDS,           # full list so UI can show dropdown
        "preview": preview,
    }), 200


# ── File upload — Step 2: confirm mapping + ingest ────────────────────────────

@app.route("/upload/confirm", methods=["POST"])
def upload_confirm():
    """
    Step 2 of bulk upload.
    Apply the user-confirmed column mapping and ingest all valid rows.

    Headers:  Authorization: <access_token>
    Body (JSON):
        {
          "upload_id": "<uuid>",
          "column_mapping": { "PatientName": "name", "BillAmt": "billing_amount", ... }
        }

    Response: validation report
        {
          "total_rows": 150,
          "imported": 143,
          "skipped": 7,
          "errors": [ { "row": 12, "reason": "..." }, ... ]
        }
    """
    err = _auth_required()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    upload_id = body.get("upload_id", "").strip()
    mapping = body.get("column_mapping", {})

    if not upload_id:
        return jsonify({"error": "Missing 'upload_id'."}), 400
    if upload_id not in _staged:
        return jsonify({"error": "upload_id not found or expired. Please re-upload the file."}), 404
    if not mapping or not isinstance(mapping, dict):
        return jsonify({"error": "Missing or invalid 'column_mapping'."}), 400

    df = _staged.pop(upload_id)         # consume — one-time use

    try:
        report = _validate_and_ingest(df, mapping)
    except Exception as e:
        logger.exception("Ingest failed")
        return jsonify({"error": f"Ingest failed: {e}"}), 500

    return jsonify(report), 200


# ── Template download ──────────────────────────────────────────────────────────

@app.route("/upload/template", methods=["GET"])
def download_template():
    """
    Download a sample CSV template showing the expected column names.
    No auth required — anyone can grab the template.

    Query param:  ?format=csv  (default) or ?format=excel
    """
    fmt = request.args.get("format", "csv").lower()

    sample = pd.DataFrame([{
        "name": "Bobby Jackson",
        "age": 30,
        "gender": "Male",
        "blood_type": "B-",
        "medical_condition": "Cancer",
        "date_of_admission": "2024-01-31",
        "doctor": "Matthew Smith",
        "hospital": "Sons And Miller",
        "insurance_provider": "Blue Cross",
        "billing_amount": 18800.00,
        "room_number": 328,
        "admission_type": "Urgent",
        "discharge_date": "2024-02-02",
        "medication": "Paracetamol",
        "test_results": "Normal",
        "latitude": -18.411,
        "longitude": -64.391,
    }])

    if fmt == "excel":
        buf = io.BytesIO()
        with pd.ExcelWriter(buf, engine="openpyxl") as writer:
            sample.to_excel(writer, index=False, sheet_name="Patients")
        buf.seek(0)
        return send_file(
            buf,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
            download_name="vaultquery_template.xlsx",
        )
    else:
        buf = io.StringIO()
        sample.to_csv(buf, index=False)
        buf.seek(0)
        return send_file(
            io.BytesIO(buf.getvalue().encode()),
            mimetype="text/csv",
            as_attachment=True,
            download_name="vaultquery_template.csv",
        )


# ── Stats (for dashboard) ──────────────────────────────────────────────────────

@app.route("/stats", methods=["GET"])
def stats():
    """
    Return aggregate stats for the admin dashboard.
    Headers:  Authorization: <access_token>
    """
    err = _auth_required()
    if err:
        return err

    total = len(data_store)
    conditions = {}
    insurers = {}

    if total > 0:
        if "medical_condition" in data_store.columns:
            conditions = data_store["medical_condition"].value_counts().to_dict()
        if "insurance_provider" in data_store.columns:
            insurers = data_store["insurance_provider"].value_counts().to_dict()

    return jsonify({
        "total_records": total,
        "conditions_breakdown": conditions,
        "insurers_breakdown": insurers,
    }), 200


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logger.info("🚀 VaultQuery — Server 0 starting on port %d …", SERVER_0_PORT)
    app.run(host="0.0.0.0", port=SERVER_0_PORT, debug=False)
