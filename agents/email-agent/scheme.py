from pydantic import BaseModel, Field
from typing import List, Optional

class EmailClassification(BaseModel):
    label: str = Field(..., description="phishing or legitimate")
    confidence: float = Field(..., ge=0.0, le=1.0)
    indicators: List[str] = Field(default_factory=list)
    has_malicious_url: bool = Field(default=False)
    recommended_action: Optional[str] = Field(..., description="Suggested action based on classification")
