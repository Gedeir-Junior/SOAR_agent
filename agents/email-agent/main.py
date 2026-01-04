from asyncio.log import logger
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from classifier import classify_email
from repository import save_classification

app = FastAPI(title="Email Phishing Agent")

class EmailInput(BaseModel):
    sender: str
    receiver: str
    date: str
    subject: str
    body: str

@app.post("/classify")
def classify(email: dict):
    result, raw = classify_email(
        sender=email["sender"],
        receiver=email["receiver"],
        date=email["date"],
        subject=email["subject"],
        body=email["body"]
    )

    try:
        save_classification(email, result, raw)
    except Exception as e:
        logger.error("DB persistence failed", exc_info=e)


    return result


