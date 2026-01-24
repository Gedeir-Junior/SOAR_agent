from fastapi import FastAPI
from app.schemes import EmailInput, ClassificationResponse
from app.model import model

app = FastAPI(
    title="BERT Phishing Classifier",
    description="Email phishing classification using BERT (CEAS dataset)",
    version="1.0.0"
)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/classify", response_model=ClassificationResponse)
def classify_email(email: EmailInput):
    text = f"Subject: {email.subject}\nBody: {email.body}"
    result = model.predict(text)
    return result
