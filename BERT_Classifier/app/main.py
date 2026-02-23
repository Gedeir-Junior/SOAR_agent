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
async def classify_email(email: EmailInput):
    try:
        # 1. Consolidação conforme o treino V4
        text_consolidado = f"From: {email.sender} | Subject: {email.subject} | Body: {email.body}"
        
        # 2. Inferência
        result = model.predict(text_consolidado)
        
        # 3. Extração de métricas
        bert_data = result["bert"]
        conf = bert_data["confidence"]
        unc = bert_data["uncertainty_score"]

        # 4. Lógica de "Zona de Dúvida" (Score 0.5)
        # Se a confiança for baixa ou houver oscilação no Dropout, marcamos como uncertain
        if conf < 0.95 or unc > 0.0001:
            label_final = "uncertain"
            action_final = "delegate_to_llm"
        else:
            label_final = bert_data["label"]
            action_final = "auto_process"

        # 5. RETORNO CORRIGIDO: Mapeia para o ClassificationResponse do schemes.py
        return {
            "classification": label_final,
            "action": action_final,
            "bert_raw": {
                "label": bert_data["label"],
                "confidence": conf,
                "uncertainty_score": unc
            }
        }
        
    except Exception as e:
        print(f"DEBUG Erro: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))