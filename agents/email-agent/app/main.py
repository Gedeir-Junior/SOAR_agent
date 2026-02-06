<<<<<<< HEAD
import logging
import time
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


=======
from fastapi import FastAPI
from pydantic import BaseModel
>>>>>>> dev
from app.classifier import classify_email

app = FastAPI()

class EmailInput(BaseModel):
    subject: str | None = None
    body: str | None = None
    sender: str | None = None
    links: list | None = []

@app.post("/classify")
async def classify(email: EmailInput):
<<<<<<< HEAD
    """
    Endpoint acionado pelo n8n.
    Recebe dados normalizados do email e retorna classificação + output bruto.
    """
    start_time = time.perf_counter()
    try:
        classification, raw_output = classify_email(email.dict())
        execution_time = time.perf_counter() - start_time

        return {
            "classification": classification.dict(),
            "raw_output": raw_output,
            "metrics": {
                "execution_time_seconds": round(execution_time)
                
            }
=======
    classification, raw_output = classify_email(email.dict())
    
    if classification is None:
        return {
            "status": "error",
            "message": "Falha na validação do modelo",
            "raw_output": raw_output
>>>>>>> dev
        }

    return {
        "status": "success",
        "classification": classification.dict(),
        "raw_output": raw_output
    }