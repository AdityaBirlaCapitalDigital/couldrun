import json
import os
import base64
import logging
import datetime
from flask import Flask, request, jsonify,Response
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from google.cloud.sql.connector import Connector
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)
app = Flask(__name__)
connector = Connector()
 
DB_CONFIG = {
    "INSTANCE_CONNECTION_NAME": os.getenv("INSTANCE_CONNECTION_NAME", "prj-abffsl-datalayer-nonprod02:asia-south1:postgresql-db-gcp-abfssl-datalayer-nonprod02"),
    "database": os.getenv("DB_NAME", "datalayerdb"),
    "user": os.getenv("DB_USER", "dataplatform2apiuat"),
    "password": os.getenv("DB_PASSWORD", "QZa~5vpXU2u7N|Zj"),
    "schema_name": os.getenv("SCHEMA_NAME", "bq"),
    "table_table": os.getenv("TABLE_NAME", "t_attention_required_api_mv"),
}
 
connector = Connector()
 
# AES Encryption Config
AES_KEY = b"a1d2c3d4f5l9972029m1a4c86d9e8l90"  # 32-byte key for AES-256
AES_IV = b"1675aldd5106eddh"  # 16-byte IV
 
# Encryption function
def encrypt(plain_text):
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode('utf-8')) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.urlsafe_b64encode(encrypted).decode('utf-8')
 
# Decryption function
def decrypt(cipher_text):
    try:
        if len(cipher_text) % 4 != 0:
            cipher_text += "=" * (4 - len(cipher_text) % 4)  # Fix padding if necessary
        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(AES_IV), backend=default_backend())
        decryptor = cipher.decryptor()
        encrypted_data = base64.urlsafe_b64decode(cipher_text)
        decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
        return decrypted.decode('utf-8')
    except Exception as e:
        return f"Error during decryption: {str(e)}"
 
def get_db_connection():
    try:
        print("Connecting to database...")
        conn = connector.connect(
            DB_CONFIG["INSTANCE_CONNECTION_NAME"],
            "pg8000",
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
            db=DB_CONFIG["database"],
            ip_type="PRIVATE"
        )
        print("Database connection established.")
        return conn
    except Exception:
        print(f"Error connecting to DB.",exc_info=True)
        return None
 
@app.route("/fetch-dues", methods=["POST"])
def fetch_dues():
    req_json = request.get_json(silent=True)
    if not req_json or 'data' not in req_json:
        return jsonify({"data": encrypt(json.dumps({"error": "Missing data parameter"}))}), 400
 
    try:
        decrypted_request = json.loads(decrypt(req_json['data']))
        customer_id = decrypted_request.get("customer_id")
        if not customer_id:
            return jsonify({"data": encrypt(json.dumps({"error": "Missing customer id"}))}), 400
    except Exception as e:
        return jsonify({"data": encrypt(json.dumps({"error": "Invalid or undecryptable data", "details": str(e)}))}), 400

    results = {
        "Credit Card": [],
        "Electricity": [],
       "Postpaid": []
    }
 
    
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({"data": encrypt(json.dumps({"error": "Failed to connect to the database"}))}), 500
 
        cursor = conn.cursor()
 
        results = {
            "Credit Card": [],
            "Electricity": [],
            "Postpaid": []
        }
 
        query = f"""
        SELECT
            bill_type,
            user_id,
            customer_id,
            provider,
            account_number,
            due_date::text,
            due_amount,
            CASE
                WHEN bill_type = 'credit_card' THEN 'Credit Card'
                WHEN bill_type = 'electricity' THEN 'Electricity'
                WHEN bill_type = 'postpaid' THEN 'Postpaid'
                ELSE bill_type
            END AS category
        FROM {DB_CONFIG['schema_name']}.{DB_CONFIG['table_table']}
        WHERE customer_id = %s
          AND bill_type IN ('credit_card', 'electricity', 'postpaid')
          AND due_date >= (CURRENT_DATE + INTERVAL '1 day')::timestamp
          AND due_date < (CURRENT_DATE + INTERVAL '3 day')::timestamp
          
        """
        cursor.execute(query, (customer_id,))
        rows = cursor.fetchall()
        columns = [desc[0] for desc in cursor.description]
 
        # Efficient grouping
        for row in rows:
            record = dict(zip(columns, row))
            bill_type = record.pop("bill_type")
            if bill_type == "credit_card":
                results["Credit Card"].append({"category": record["category"],
                    "cc_user_id": record["user_id"],
                    "cc_customer_id": record["customer_id"],
                    "cc_bank": record["provider"],
                    "cc_account_no": record["account_number"],
                    "cc_due_date": record["due_date"],
                    "cc_due_amount": record["due_amount"]
                })
            elif bill_type == "electricity":
                results["Electricity"].append({"category": record["category"],
                    "user_id": record["user_id"],
                    "customer_id": record["customer_id"],
                    "electricity_provider": record["provider"],
                    "electricity_consumer_id": record["consumer_id"],
                    "electricity_due_date": record["due_date"],
                    "electricity_due_amount": record["due_amount"]
                })
            elif bill_type == "postpaid":
                results["Postpaid"].append({"category": record["category"],
                    "user_id": record["user_id"],
                    "customer_id": record["customer_id"],
                    "postpaid_provider": record["provider"],
                    "postpaid_consumer_id": record["consumer_id"],
                    "postpaid_due_date": record["due_date"],
                    "postpaid_due_amount": record["due_amount"]
                })
 
        cursor.close()
        conn.close()
 
 
        if not any(results.values()):
            return jsonify({"data": encrypt(json.dumps({"error": "No dues found for given customer id"}))}), 404
 
        return Response(json.dumps({"data": encrypt(json.dumps(results))}), mimetype="application/json")
 
    except Exception:
        log.error(f"Exception occurred.",exc_info=True)
        return jsonify({"data": encrypt(json.dumps({"error": "Query not executed"}))}), 500
 
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
 
 
