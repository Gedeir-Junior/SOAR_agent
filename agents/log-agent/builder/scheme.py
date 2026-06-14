from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional

from pydantic import BaseModel, Field, computed_field, field_validator


_FONTE_ALIASES: dict[str, str] = {
  "network": "rede", "net": "rede", "network_traffic": "rede",
  "linux": "linux_syslog", "syslog": "linux_syslog", "auditd": "linux_syslog", "journald": "linux_syslog",
  "windows": "windows_eventlog", "windows_event": "windows_eventlog", "winevt": "windows_eventlog",
  "eventlog": "windows_eventlog", "event_log": "windows_eventlog", "winevent": "windows_eventlog",
  "macos": "macos_unified_log", "mac": "macos_unified_log", "osx": "macos_unified_log",
  "unified_log": "macos_unified_log", "macos_log": "macos_unified_log",
  # Containers/Cloud → N/A via linux_syslog (serão sobrescritos no normalize)
  "kubernetes": "linux_syslog", "kubernetes_audit_log": "linux_syslog",
  "kubernetes_audit_logs": "linux_syslog", "kubernetes_audit": "linux_syslog",
  "k8s": "linux_syslog", "k8s_audit": "linux_syslog", "container": "linux_syslog",
  "containers": "linux_syslog", "docker": "linux_syslog",
  "cloud": "rede", "cloud_audit_log": "rede", "cloud_log": "rede",
  "iaas": "rede", "saas": "rede", "office365": "rede", "office_365": "rede",
  "azure": "rede", "azure_ad": "rede", "entra_id": "rede",
  "google_workspace": "rede", "gws": "rede", "aws": "rede",
  "cloudtrail": "rede", "gcp": "rede",
}


class LogFonte(str, Enum):
  LINUX_SYSLOG      = "linux_syslog"
  WINDOWS_EVENTLOG  = "windows_eventlog"
  MACOS_UNIFIED_LOG = "macos_unified_log"
  REDE              = "rede"

  @classmethod
  def _missing_(cls, value: object) -> "LogFonte | None":
    if not isinstance(value, str):
      return None
    normalized = _FONTE_ALIASES.get(value.lower(), value.lower())
    for member in cls:
      if member.value == normalized:
        return member
    return None

class PadraoLog(BaseModel):
  fonte: LogFonte = Field(description="Origem do log ao qual o padrão se aplica.")
  exemplos: List[str] = Field(
    min_length=1,
    description="Linhas brutas ou trechos realistas de log que indicam a técnica.",
  )
  event_ids: List[str] = Field(
    default_factory=list,
    description="Event IDs relevantes (Windows/Sysmon) ou códigos equivalentes.",
  )
  indicadores_regex: List[str] = Field(
    default_factory=list,
    description="Expressões regulares opcionais para pré-filtragem determinística.",
  )

  @field_validator("event_ids", mode="before")
  @classmethod
  def coerce_event_ids_to_str(cls, v: Any) -> list[str]:
    if not isinstance(v, list):
      return v
    return [str(i) if not isinstance(i, str) else i for i in v]


class ThreatDetectionPattern(BaseModel):
  tecnica_id: str = Field(
    description="ID oficial MITRE ATT&CK (ex.: T1595.003).",
    pattern=r"^T\d{4}(\.\d{3})?$",
  )
  nome_tecnica: str
  tatica: str = Field(description="Nome da tática (ex.: Reconnaissance).")
  tatica_id: str = Field(
    description="ID STIX da tática (ex.: TA0043).",
    pattern=r"^TA\d{4}$",
  )
  descricao_mitre: str = Field(
    description="Descrição resumida original do MITRE, usada como contexto base.",
  )
  descricao_semantica_log: str = Field(
    description=(
      "Como a técnica se manifesta em arquivos de log: volume, processos, "
      "fluxos de rede, anomalias temporais e sinais comportamentais."
    )
  )
  plataformas_mitre: List[str] = Field(
    default_factory=list,
    description="Plataformas MITRE associadas (Linux, Windows, macOS, Network...).",
  )
  is_subtecnica: bool = False
  tecnica_pai_id: Optional[str] = Field(
    default=None,
    description="ID da técnica pai quando is_subtecnica=True.",
  )
  padroes_log: List[PadraoLog] = Field(
    min_length=1,
    description="Padrões agrupados por fonte de log; substitui campos fixos por SO.",
  )
  palavras_chave_filtro: List[str] = Field(
    min_length=1,
    description=(
      "Termos estáticos para busca lexical rápida: comandos, Event IDs, "
      "protocolos, nomes de processo ou códigos de erro."
    ),
  )
  severidade_sugerida: str = Field(
    default="medium",
    description="Severidade sugerida para o relatório: low | medium | high | critical.",
  )
  confianca_padrao: float = Field(
    default=0.7,
    ge=0.0,
    le=1.0,
    description="Confiança base do padrão gerado (ajustável após validação humana).",
  )

  @computed_field
  @property
  def texto_busca_vetorial(self) -> str:
    partes = [
      f"Técnica {self.tecnica_id} ({self.nome_tecnica})",
      f"Tática: {self.tatica} ({self.tatica_id})",
      self.descricao_semantica_log,
      f"Palavras-chave: {', '.join(self.palavras_chave_filtro)}",
    ]
    for padrao in self.padroes_log:
      partes.append(f"Fonte {padrao.fonte.value}: {' | '.join(padrao.exemplos[:3])}")
    return "\n".join(partes)


class TacticDataset(BaseModel):
  tatica: str
  tatica_id: str
  gerado_em: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
  modelo_llm: str
  versao_schema: str = "1.0"
  padroes: List[ThreatDetectionPattern]

  def to_qdrant_payloads(self) -> List[dict]:
    return [
      {
        "id": padrao.tecnica_id,
        "texto_busca_vetorial": padrao.texto_busca_vetorial,
        "payload": padrao.model_dump(),
      }
      for padrao in self.padroes
    ]


class DatasetManifest(BaseModel):
  stix_arquivo: str
  taticas_concluidas: List[str] = Field(default_factory=list)
  taticas_pendentes: List[str] = Field(default_factory=list)
  total_padroes: int = 0
  atualizado_em: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))