from fastapi import FastAPI
from pydantic import BaseModel
from app.classifier import classify_email

app = FastAPI()

class EmailInput(BaseModel):
    subject: str | None = None
    body: str | None = None
    sender: str | None = None
    links: list | None = []

@app.post("/classify")
async def classify(email: EmailInput):
    classification, raw_output = classify_email(email.dict())
    
    if classification is None:
        return {
            "status": "error",
            "message": "Falha na validação do modelo",
            "raw_output": raw_output
        }

    return {
        "status": "success",
        "classification": classification.dict(),
        "raw_output": raw_output
    }