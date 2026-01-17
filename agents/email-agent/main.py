import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from classifier import classify_email

logger = logging.getLogger("email_agent")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Email Phishing Agent")

class EmailInput(BaseModel):
    sender: str
    receiver: str
    date: str
    subject: str
    body: str

@app.post("/classify")
async def classify(email: EmailInput):
    try:
        result, raw = classify_email(
            sender=email.sender,
            receiver=email.receiver,
            date=email.date,
            subject=email.subject,
            body=email.body
        )
    except ValueError as e:
        logger.exception("Failed to parse LLM output")
        raise HTTPException(status_code=502, detail=str(e))
    except Exception as e:
        # LLM or upstream services (Ollama) may fail or timeout; report as 502
        logger.exception("LLM classification failed")
        raise HTTPException(status_code=502, detail=str(e))

    response = {
        "email": email.dict(),
        "classification": result.dict() if hasattr(result, "dict") else result,
        "raw_output": raw
    }

    return response


@app.get("/health")
async def health():
    return {"ok": True}


