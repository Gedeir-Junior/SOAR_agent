import psycopg2
import os
import json

def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        connect_timeout=5
    )

def save_classification(email_data: dict, result, raw_llm_output: str):
    try:
        conn = get_connection()
        cur = conn.cursor()

        query = """
        INSERT INTO email_classification_results (
            sender, receiver, email_date, subject, body,
            predicted_label, confidence, has_malicious_url, indicators,
            model_name, model_version, raw_llm_output
        )
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """

        cur.execute(query, (
            email_data["sender"],
            email_data["receiver"],
            email_data["date"],
            email_data["subject"],
            email_data["body"],
            result.label,
            result.confidence,
            result.has_malicious_url,
            result.indicators,
            os.getenv("MODEL_NAME"),
            os.getenv("MODEL_VERSION"),
            json.loads(raw_llm_output) if raw_llm_output else None
        ))

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        # Fail-safe: loga, mas NÃO derruba o agente
        print(f"[DB WARNING] Failed to persist classification: {e}")
