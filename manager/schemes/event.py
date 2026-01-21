from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4
from datetime import datetime

from .common import SeverityLevel, IndicatorType

class AssetContext(BaseModel):

    """
    Recursos que podem ser afetados pelo evento.
    """
    user: Optional[str] = None
    host: Optional[str] = None
    ip: Optional[str] = None
    email: Optional[str] = None

class Indicator(BaseModel):

    """
    Indicadores associados ao evento.
    """
    type: IndicatorType
    value: str
    description: Optional[str] = None

class EventContext(BaseModel):

    """
    Contexto adicional do evento.
    """
    summary: str
    raw_data: Dict[str, Any] = Field(default_factory=dict)

class SecurityEvent(BaseModel):

    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    source_agent: str = Field(..., description="Agente que gerou o evento.")
    event_type: str = Field(..., default="security_alert", description="Tipo do evento de segurança.")
    category: str = Field(..., description="Categoria do evento de segurança.")
    confidence: float = Field(..., ge=0.0, le=100.0, description="Nível de confiança do evento.")
    severity: SeverityLevel = Field(..., description="Nível de severidade do evento.")
    assets: AssetContext = Field(default_factory=AssetContext)
    Indicators: List[Indicator] = Field(default_factory=list)
    context: EventContext
    