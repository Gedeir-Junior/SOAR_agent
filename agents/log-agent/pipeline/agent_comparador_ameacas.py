"""
agents/agente_comparador_ameacas.py

Agente 2 — Comparador de Ameaças

Recebe a lista de LogTraduzido do Agente 1, faz busca híbrida no Qdrant
para cada linha relevante e consolida as correspondências em AmeacaDetectada,
agrupando por técnica MITRE e calculando evidências acumuladas.

Saída: RelatorioAmeacas, estrutura de dados completa usada pelo gerador de PDF.
"""
from __future__ import annotations

import os
import sys
import json
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from pipeline.agente_tradutor_logs import LogTraduzido
from retriever.semantic_retriever import ResultadoBusca, RetrieverSemantico

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
GROQ_API_KEY  = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL    = os.getenv("GROQ_MODEL", "meta-llama/llama-4-scout-17b-16e-instruct")
GROQ_API_URL  = "https://api.groq.com/openai/v1/chat/completions"
LLM_RETRIES   = int(os.getenv("LLM_RETRIES", "3"))
TOP_K_BUSCA   = int(os.getenv("COMPARADOR_TOP_K", "3"))
LIMIAR_SCORE  = float(os.getenv("COMPARADOR_SCORE_THRESHOLD", "0.8"))

# Severidades que merecem busca (ignora linhas de info puro)
SEVERIDADES_RELEVANTES = {"low", "medium", "high", "critical"}

# Mapeamento plataforma detectada → termos aceitos nas plataformas MITRE.
# Nível de módulo (em vez de local ao método) para reuso pelo pipeline_contextual
# (ver pipeline_contextual/agente_comparador_contextual.py), sem duplicar o dict.
_PLATAFORMA_MITRE_MAP: dict[str, set[str]] = {
    "linux":      {"linux", "unix", "esxi", "network devices", "containers"},
    "windows":    {"windows", "azure ad", "office 365", "saas", "iaas"},
    "macos":      {"macos", "linux", "unix"},
    "network":    {"network devices", "linux", "windows"},
    "desconhecida": set(),  # sem filtro de plataforma
}

_SYSTEM_PROMPT = (
    "Você é um analista de segurança sênior especializado em resposta a incidentes. "
    "Analise evidências de logs e técnicas MITRE ATT&CK e forneça análise técnica precisa. "
    "Responda SOMENTE com JSON válido, sem markdown nem explicações extras."
)


# ---------------------------------------------------------------------------
# Dataclasses de saída
# ---------------------------------------------------------------------------
@dataclass
class EvidenciaLog:
    numero_linha: int
    linha_original: str
    descricao_comportamental: str
    score_similaridade: float


@dataclass
class AmeacaDetectada:
    tecnica_id: str
    nome_tecnica: str
    tatica: str
    tatica_id: str
    severidade: str
    confianca_media: float
    descricao_mitre: str
    descricao_semantica_log: str
    plataformas_mitre: list[str]
    evidencias: list[EvidenciaLog]
    analise_llm: str = ""             # síntese gerada pelo LLM
    recomendacoes: list[str] = field(default_factory=list)
    url_mitre: str = ""

    @property
    def score_risco(self) -> float:
        """Score de risco composto: média dos scores × peso da severidade.

        Penalidade de 30% aplicada quando há apenas 1 evidência em severidade
        alta/crítica — uma única linha raramente confirma uma técnica grave.
        """
        pesos = {"low": 0.25, "medium": 0.5, "high": 0.8, "critical": 1.0}
        peso = pesos.get(self.severidade.lower(), 0.5)
        media_scores = (
            sum(e.score_similaridade for e in self.evidencias) / len(self.evidencias)
            if self.evidencias else 0.0
        )
        penalidade = (
            0.7
            if len(self.evidencias) == 1 and self.severidade.lower() in {"high", "critical"}
            else 1.0
        )
        return round(media_scores * peso * self.confianca_media * penalidade, 4)

    @property
    def contagem_evidencias(self) -> int:
        return len(self.evidencias)


@dataclass
class RelatorioAmeacas:
    arquivo_log: str
    total_linhas_analisadas: int
    total_ameacas_detectadas: int
    ameacas: list[AmeacaDetectada]
    resumo_executivo: str = ""
    severidade_geral: str = "low"
    timestamp_geracao: str = ""

    def ameacas_por_severidade(self, severidade: str) -> list[AmeacaDetectada]:
        return [a for a in self.ameacas if a.severidade.lower() == severidade.lower()]

    def taticas_unicas(self) -> list[str]:
        return sorted({a.tatica for a in self.ameacas})


# ---------------------------------------------------------------------------
# Helpers LLM
# ---------------------------------------------------------------------------
def _parse_retry_after(response: requests.Response) -> float:
    for header in ("x-ratelimit-reset-requests", "retry-after", "Retry-After"):
        val = response.headers.get(header, "")
        if not val:
            continue
        minutes = re.search(r"(\d+)m", val)
        seconds = re.search(r"(\d+)s", val)
        total = 0.0
        if minutes:
            total += int(minutes.group(1)) * 60
        if seconds:
            total += int(seconds.group(1))
        if total > 0:
            return min(max(total + 1.0, 5.0), 120.0)
        try:
            return min(max(float(val) + 1.0, 5.0), 120.0)
        except ValueError:
            pass
    return 30.0


def _chamar_groq(prompt: str) -> str:
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY não definida no .env")
    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": prompt},
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }
    last_error: Exception | None = None
    for attempt in range(LLM_RETRIES + 1):
        try:
            resp = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=60)
            if resp.status_code == 429:
                wait = _parse_retry_after(resp)
                print(f"  [comparador 429] aguardando {wait:.1f}s…")
                time.sleep(wait)
                attempt = max(attempt - 1, 0)
                continue
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except requests.HTTPError as exc:
            last_error = exc
            if attempt < LLM_RETRIES:
                time.sleep(2 ** attempt)
                continue
            break
        except requests.RequestException as exc:
            last_error = exc
            if attempt < LLM_RETRIES:
                time.sleep(2 ** attempt)
                continue
            break
    raise RuntimeError(f"Falha ao consultar Groq (comparador): {last_error}") from last_error


# ---------------------------------------------------------------------------
# Geração de análise LLM por ameaça
# ---------------------------------------------------------------------------
def _gerar_analise_ameaca(ameaca: AmeacaDetectada) -> tuple[str, list[str]]:
    """Pede ao LLM uma síntese técnica e recomendações para uma ameaça detectada."""
    evidencias_str = "\n".join(
        f"  L{e.numero_linha} (score={e.score_similaridade:.3f}): {e.linha_original}"
        for e in ameaca.evidencias[:5]  # máximo 5 evidências no prompt
    )
    prompt = f"""Técnica MITRE detectada: {ameaca.tecnica_id} — {ameaca.nome_tecnica}
Tática: {ameaca.tatica} ({ameaca.tatica_id})
Severidade: {ameaca.severidade}
Descrição MITRE: {ameaca.descricao_mitre}
Como aparece em logs: {ameaca.descricao_semantica_log[:300]}

Evidências encontradas no arquivo de log:
{evidencias_str}

Retorne SOMENTE este JSON:
{{
  "analise": "<análise técnica em português de 3-5 frases: o que o atacante está fazendo, qual o risco imediato, quais sistemas estão expostos>",
  "recomendacoes": [
    "<ação de resposta 1>",
    "<ação de resposta 2>",
    "<ação de resposta 3>"
  ]
}}"""

    try:
        raw = _chamar_groq(prompt)
        raw = raw.strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```(?:json)?\s*", "", raw)
            raw = re.sub(r"\s*```$", "", raw)
        data = json.loads(raw)
        return data.get("analise", ""), data.get("recomendacoes", [])
    except Exception as exc:
        print(f"  [AVISO] Análise LLM falhou para {ameaca.tecnica_id}: {exc}", file=sys.stderr)
        return "", []


def _gerar_resumo_executivo(relatorio: RelatorioAmeacas) -> str:
    """Gera resumo executivo do relatório completo."""
    ameacas_str = "\n".join(
        f"  - {a.tecnica_id} ({a.nome_tecnica}): {a.contagem_evidencias} evidência(s), severidade={a.severidade}"
        for a in relatorio.ameacas[:10]
    )
    prompt = f"""Analise o seguinte sumário de detecção de ameaças em um arquivo de log:

Arquivo analisado: {relatorio.arquivo_log}
Total de linhas analisadas: {relatorio.total_linhas_analisadas}
Ameaças detectadas: {relatorio.total_ameacas_detectadas}
Táticas únicas identificadas: {', '.join(relatorio.taticas_unicas())}

Técnicas detectadas:
{ameacas_str}

Retorne SOMENTE este JSON:
{{
  "resumo_executivo": "<resumo em português de 4-6 frases para audiência executiva não-técnica: o que foi encontrado, qual o risco geral, qual a urgência de resposta>",
  "severidade_geral": "<low | medium | high | critical>"
}}"""

    try:
        raw = _chamar_groq(prompt)
        raw = raw.strip()
        if raw.startswith("```"):
            raw = re.sub(r"^```(?:json)?\s*", "", raw)
            raw = re.sub(r"\s*```$", "", raw)
        data = json.loads(raw)
        return data.get("resumo_executivo", ""), data.get("severidade_geral", "medium")
    except Exception as exc:
        print(f"  [AVISO] Resumo executivo falhou: {exc}", file=sys.stderr)
        return "", "medium"


# ---------------------------------------------------------------------------
# Agente principal
# ---------------------------------------------------------------------------
class AgenteComparadorAmeacas:
    def __init__(
        self,
        top_k: int = TOP_K_BUSCA,
        limiar_score: float = LIMIAR_SCORE,
        gerar_analise_llm: bool = True,
    ) -> None:
        self.top_k = top_k
        self.limiar_score = limiar_score
        self.gerar_analise_llm = gerar_analise_llm
        self._retriever = RetrieverSemantico(top_k=top_k, limiar_score=limiar_score)

    def analisar(
        self,
        traducoes: list[LogTraduzido],
        nome_arquivo_log: str = "desconhecido",
    ) -> RelatorioAmeacas:
        """
        Ponto de entrada principal: recebe traduções e retorna relatório completo.
        """
        from datetime import datetime, timezone
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        print(f"[*] Comparador: {len(traducoes)} linhas traduzidas para análise…")

        # Detecta plataforma predominante
        plataforma_predominante = self._detectar_plataforma_predominante(traducoes)
        print(f"[*] Plataforma predominante: {plataforma_predominante}")

        # Agrupa evidências por tecnica_id
        mapa_ameacas: dict[str, dict] = defaultdict(lambda: {
            "resultado": None,
            "evidencias": [],
        })

        linhas_relevantes = [
            t for t in traducoes
            if t.severidade_inferida in SEVERIDADES_RELEVANTES
        ]
        print(f"[*] {len(linhas_relevantes)} linhas com severidade relevante para busca.")

        plataformas_aceitas = _PLATAFORMA_MITRE_MAP.get(plataforma_predominante, set())

        for log in linhas_relevantes:

            resultados = self._retriever.buscar_hibrido(
                query=log.descricao_comportamental,
                keywords=log.keywords_extraidas,
                top_k=self.top_k,
                limiar_score=self.limiar_score,
            )

            for resultado in resultados:
                # Descarta técnicas incompatíveis com a plataforma do log.
                # Ex: T1059.012 (ESXi) não deve aparecer em logs puramente Linux;
                # T1098.006 (Containers) não deve aparecer sem evidência Kubernetes.
                if plataformas_aceitas:
                    plataformas_tecnica = {p.lower() for p in resultado.plataformas_mitre}
                    if not plataformas_tecnica.intersection(plataformas_aceitas):
                        continue

                # Descarta resultados com score vetorial abaixo do limiar configurado.
                # buscar_hibrido pode retornar itens lexicais com score=1.0 artificial;
                # o score_combinado (score × confiança_padrão) é a métrica real de qualidade.
                score_efetivo = resultado.score if resultado.score < 1.0 else resultado.score_combinado
                if score_efetivo < self.limiar_score:
                    continue

                tid = resultado.tecnica_id
                if mapa_ameacas[tid]["resultado"] is None:
                    mapa_ameacas[tid]["resultado"] = resultado

                mapa_ameacas[tid]["evidencias"].append(
                    EvidenciaLog(
                        numero_linha=log.numero_linha,
                        linha_original=log.linha_original,
                        descricao_comportamental=log.descricao_comportamental,
                        score_similaridade=resultado.score,
                    )
                )

        # Constrói AmeacaDetectada e deduplicar evidências por linha
        ameacas: list[AmeacaDetectada] = []
        for tid, dados in mapa_ameacas.items():
            resultado: ResultadoBusca = dados["resultado"]
            evidencias_raw: list[EvidenciaLog] = dados["evidencias"]

            # Deduplica por numero_linha, mantém maior score
            ev_por_linha: dict[int, EvidenciaLog] = {}
            for ev in evidencias_raw:
                if ev.numero_linha not in ev_por_linha or ev.score_similaridade > ev_por_linha[ev.numero_linha].score_similaridade:
                    ev_por_linha[ev.numero_linha] = ev
            evidencias_unicas = sorted(ev_por_linha.values(), key=lambda e: e.numero_linha)

            confianca_media = round(
                sum(e.score_similaridade for e in evidencias_unicas) / len(evidencias_unicas), 4
            )

            ameaca = AmeacaDetectada(
                tecnica_id=resultado.tecnica_id,
                nome_tecnica=resultado.nome_tecnica,
                tatica=resultado.tatica,
                tatica_id=resultado.tatica_id,
                severidade=resultado.severidade_sugerida,
                confianca_media=confianca_media,
                descricao_mitre=resultado.descricao_mitre,
                descricao_semantica_log=resultado.descricao_semantica_log,
                plataformas_mitre=resultado.plataformas_mitre,
                evidencias=evidencias_unicas,
                url_mitre=f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}",
            )
            ameacas.append(ameaca)

        # Ordena por score_risco decrescente
        ameacas.sort(key=lambda a: a.score_risco, reverse=True)

        # Gera análise LLM por ameaça (opcional)
        if self.gerar_analise_llm:
            print(f"[*] Gerando análise LLM para {len(ameacas)} ameaça(s)…")
            for i, ameaca in enumerate(ameacas, 1):
                print(f"  [{i}/{len(ameacas)}] Analisando {ameaca.tecnica_id}…")
                analise, recomendacoes = _gerar_analise_ameaca(ameaca)
                ameaca.analise_llm = analise
                ameaca.recomendacoes = recomendacoes

        # Monta relatório base
        relatorio = RelatorioAmeacas(
            arquivo_log=nome_arquivo_log,
            total_linhas_analisadas=len(traducoes),
            total_ameacas_detectadas=len(ameacas),
            ameacas=ameacas,
            timestamp_geracao=timestamp,
        )

        # Gera resumo executivo
        if ameacas:
            print("[*] Gerando resumo executivo…")
            resumo, severidade_geral = _gerar_resumo_executivo(relatorio)
            relatorio.resumo_executivo = resumo
            relatorio.severidade_geral = severidade_geral

        print(f"[+] Comparador concluído: {len(ameacas)} ameaça(s) detectada(s).")
        return relatorio

    def _detectar_plataforma_predominante(self, traducoes: list[LogTraduzido]) -> str:
        """Detecta a plataforma predominante entre os logs"""
        from collections import Counter
        
        plataformas = [t.plataforma for t in traducoes if t.plataforma != "desconhecida"]
        
        if not plataformas:
            return "desconhecida"
        
        contador = Counter(plataformas)
        plataforma_predominante = contador.most_common(1)[0][0]
        
        return plataforma_predominante


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse, dataclasses

    parser = argparse.ArgumentParser(description="Compara traduções de log com banco vetorial MITRE.")
    parser.add_argument("traducoes_json", type=Path, help="JSON de saída do agente tradutor.")
    parser.add_argument("--saida", type=Path, default=None)
    parser.add_argument("--top-k", type=int, default=TOP_K_BUSCA)
    parser.add_argument("--threshold", type=float, default=LIMIAR_SCORE)
    parser.add_argument("--sem-llm", action="store_true", help="Pula análise LLM por ameaça.")
    args = parser.parse_args()

    dados = json.loads(args.traducoes_json.read_text(encoding="utf-8"))
    traducoes = [LogTraduzido(**d) for d in dados]

    agente = AgenteComparadorAmeacas(
        top_k=args.top_k,
        limiar_score=args.threshold,
        gerar_analise_llm=not args.sem_llm,
    )
    relatorio = agente.analisar(traducoes, nome_arquivo_log=args.traducoes_json.stem)

    if args.saida:
        import dataclasses as dc
        args.saida.write_text(
            json.dumps(dc.asdict(relatorio), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"[+] Relatório salvo em: {args.saida}")
    else:
        for ameaca in relatorio.ameacas:
            print(f"\n[{ameaca.severidade.upper()}] {ameaca.tecnica_id} — {ameaca.nome_tecnica}")
            print(f"  Evidências: {ameaca.contagem_evidencias} | Score risco: {ameaca.score_risco}")