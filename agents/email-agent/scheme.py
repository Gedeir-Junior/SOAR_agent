from pydantic import BaseModel, Field
from typing import List

class EmailClassification(BaseModel):
    label: str = Field(..., description="phishing or legitimate")
    confidence: float = Field(..., ge=0.0, le=1.0)
    indicators: List[str]
    has_malicious_url: bool
    recommended_action: str
