from pydantic import BaseModel, Field
from typing import Optional

class EmailInput(BaseModel):
    # Campos individuais que o seu main.py tenta acessar
    sender: str = Field(..., description="E-mail do remetente")
    subject: str = Field(..., description="Assunto do e-mail")
    body: str = Field(..., description="Corpo do e-mail")
    receiver: Optional[str] = Field("unknown", description="E-mail do destinatário")
    links: Optional[str] = Field("", description="Links encontrados no e-mail")

class BertMetrics(BaseModel):
    label: str
    confidence: float = Field(..., description="Confiança calibrada via Temperature Scaling")
    uncertainty_score: float = Field(..., description="Variância calculada via Monte Carlo Dropout")

class ClassificationResponse(BaseModel):
    classification: str = Field(..., description="Resultado final: phishing, legitimate ou uncertain")
    action: str = Field(..., description="Ação recomendada: auto_process ou delegate_to_llm")
    bert_raw: BertMetrics