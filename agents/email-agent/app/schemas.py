from typing import List, Optional
from pydantic import BaseModel, Field

class AnaliseComparativa(BaseModel):
    sinais_de_seguranca: List[str] = Field(default_factory=list)
    sinais_de_ameaca: List[str] = Field(default_factory=list)
    justificativa_final: str = Field(..., description="Justificativa detalhada da decisão.")

class EmailAnalysisResponse(BaseModel):
    label: str = Field(..., description="'phishing', uncertain ou 'legitimate'")
    confidence: float = Field(..., ge=0.0, le=1.0)
    analise_comparativa: AnaliseComparativa
    recommended_action: Optional[str] = Field(default="deliver_to_inbox")