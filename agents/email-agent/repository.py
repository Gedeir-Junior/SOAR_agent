import psycopg2
import os
import json


def get_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD")
    )


def save_classification(email, result, raw_output):
    """
    Persiste o resultado da classificação no Postgres
    """

    conn = get_connection()
    cur = conn.cursor()

    query = """
    INSERT INTO email_classification_results (
        sender,
        receiver,
        email_date,
        subject,
        body,
        predicted_label,
        confidence,
        has_malicious_url,
        indicators,
        model_name,
        raw_llm_output
    )
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """

    cur.execute(
        query,
        (
            email["sender"],
            email["receiver"],
            email["date"],
            email["subject"],
            email["body"],
            result.label,
            result.confidence,
            result.has_malicious_url,
            result.indicators,
            os.getenv("MODEL_NAME"),
            json.dumps(raw_output)
        )
    )

    conn.commit()
    cur.close()
    conn.close()
