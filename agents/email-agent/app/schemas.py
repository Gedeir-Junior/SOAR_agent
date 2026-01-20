from typing import List, Optional
from pydantic import BaseModel, Field

class ExampleEvidence(BaseModel):
    phishing_similar: int = Field(..., ge=0, description="Número de exemplos semelhantes de phishing.")
    legitimate_similar: int = Field(..., ge=0, description="Número de exemplos semelhantes legítimos.")
    sources: List[str] = Field(default_factory=list, description="Fontes dos exemplos.")

class Reasoninig(BaseModel):
    guidelines_evidence: List[str] = Field(default_factory=list, description="Evidências baseadas em diretrizes.")
    example_evidence: ExampleEvidence
    technical_indicators: List[str] = Field(default_factory=list, description="Evidências técnicas coletadas.")

class EmailAnalysisResponse(BaseModel):
    label: str = Field(..., description="Legítimo ou Phishing.")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Nível de confiança na classificação.")
    reasoning: Reasoninig
    indicators: List[str] = Field(default_factory=list, description="Indicadores adicionais relacionados ao e-mail.")
    has_malicious_url: Optional[bool] = Field(None, description="Indica se o email possuí algum link malicioso.")
    recommended_action: Optional[str] = Field(None, description="Ação recomendada para o e-mail analisado.")