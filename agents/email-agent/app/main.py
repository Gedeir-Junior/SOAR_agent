import logging
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.classifier import classify_email

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("email_agent")

app = FastAPI(
    title="Email Phishing Agent",
    description="SOAR Email Analysis Agent"
)


class EmailInput(BaseModel):
    subject: str | None = None
    body: str | None = None


@app.post("/classify")
async def classify(email: EmailInput):
    """
    Endpoint acionado pelo n8n.
    Recebe dados normalizados do email e retorna classificação + output bruto.
    """
    try:
        classification, raw_output = classify_email(email.dict())

        return {
            "classification": classification.dict(),
            "raw_output": raw_output
        }

    except ValueError as e:
        logger.exception("Erro ao validar output do modelo")
        raise HTTPException(status_code=502, detail=str(e))

    except Exception as e:
        logger.exception("Erro interno no email-agent")
        raise HTTPException(status_code=500, detail="Erro interno no email-agent")


@app.get("/health")
async def health():
    return {"status": "ok"}
