"""
agents/agente_tradutor_logs.py

Agente 1 — Tradutor de Logs

Recebe um arquivo de log bruto, processa em lotes e usa o LLM (Groq) para
traduzir cada linha ou bloco para uma descrição comportamental em português,
adequada para busca semântica no banco vetorial.

Saída: lista de LogTraduzido, cada um contendo a linha original, a
descrição comportamental e as keywords extraídas.
"""
from __future__ import annotations

import os
import sys
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL   = os.getenv("GROQ_MODEL", "meta-llama/llama-4-scout-17b-16e-instruct")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
LLM_RETRIES  = int(os.getenv("LLM_RETRIES", "3"))

# Quantas linhas de log processar por chamada à API
BATCH_SIZE   = int(os.getenv("TRADUTOR_BATCH_SIZE", "15"))

_SYSTEM_PROMPT = (
    "Você é um analista de segurança sênior especializado em análise de logs. "
    "Sua tarefa é descrever o que cada linha ou grupo de linhas de log "
    "significa do ponto de vista de comportamento e segurança. "
    "Responda SOMENTE com JSON válido, sem markdown nem explicações."
)


# ---------------------------------------------------------------------------
# Dataclass de saída
# ---------------------------------------------------------------------------
@dataclass
class LogTraduzido:
    linha_original: str
    numero_linha: int
    descricao_comportamental: str        # texto rico para busca semântica
    keywords_extraidas: list[str]        # termos para busca lexical
    fonte_inferida: str = "desconhecida" # linux_syslog, windows_eventlog, rede, etc.
    severidade_inferida: str = "info"    # info | low | medium | high | critical
    plataforma: str = "desconhecida"     # linux | windows | macos | network | desconhecida
    tags_plataforma: list[str] = None    # Tags para filtrar buscas no Qdrant


# ---------------------------------------------------------------------------
# Helpers de chamada ao Groq
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
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }

    last_error: Exception | None = None
    for attempt in range(LLM_RETRIES + 1):
        try:
            resp = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=60)
            if resp.status_code == 429:
                wait = _parse_retry_after(resp)
                print(f"  [tradutor 429] aguardando {wait:.1f}s…")
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

    raise RuntimeError(f"Falha ao consultar Groq (tradutor): {last_error}") from last_error


# ---------------------------------------------------------------------------
# Construção do prompt de tradução
# ---------------------------------------------------------------------------
def _build_prompt_traducao(linhas: list[tuple[int, str]]) -> str:
    bloco = "\n".join(f"{num}: {linha}" for num, linha in linhas)
    return f"""Analise as seguintes linhas de log e retorne um JSON com a estrutura abaixo.
Para cada linha retorne um objeto dentro do array "traducoes".

Estrutura obrigatória:
{{
  "traducoes": [
    {{
      "numero_linha": <int>,
      "descricao_comportamental": "<descrição detalhada do comportamento em português, mínimo 20 palavras>",
      "keywords_extraidas": ["<termo1>", "<termo2>", ...],
      "fonte_inferida": "<linux_syslog | windows_eventlog | macos_unified_log | rede | desconhecida>",
      "severidade_inferida": "<info | low | medium | high | critical>"
    }}
  ]
}}

Critérios:
- descricao_comportamental: explique O QUE está acontecendo (processo, usuário, IP, porta, ação) e POR QUE é relevante para segurança.
- keywords_extraidas: comandos, IPs notáveis, Event IDs, nomes de processo, portas, protocolos.
- Linhas de log com baixo valor de segurança (rotina normal) devem ter severidade_inferida="info".
- Nunca invente dados que não estão na linha de log.

Linhas de log:
{bloco}
"""


# ---------------------------------------------------------------------------
# Parseador de resposta
# ---------------------------------------------------------------------------
def _parsear_resposta(raw: str, linhas_originais: dict[int, str], plataforma: str = "desconhecida", tags_plataforma: list[str] = None) -> list[LogTraduzido]:
    if tags_plataforma is None:
        tags_plataforma = []
        
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON inválido na resposta do tradutor: {exc}\n{raw[:300]}") from exc

    traducoes = data.get("traducoes", [])
    resultados: list[LogTraduzido] = []

    for item in traducoes:
        num = item.get("numero_linha", 0)
        resultados.append(
            LogTraduzido(
                linha_original=linhas_originais.get(num, ""),
                numero_linha=num,
                descricao_comportamental=item.get("descricao_comportamental", ""),
                keywords_extraidas=item.get("keywords_extraidas", []),
                fonte_inferida=item.get("fonte_inferida", "desconhecida"),
                severidade_inferida=item.get("severidade_inferida", "info"),
                plataforma=plataforma,
                tags_plataforma=tags_plataforma.copy(),
            )
        )

    return resultados


# ---------------------------------------------------------------------------
# Agente principal
# ---------------------------------------------------------------------------
class AgenteTradutorLogs:
    """
    Traduz um arquivo de log completo para descrições comportamentais.

    Parâmetros:
        batch_size: linhas por chamada ao LLM (padrão: 15)
        ignorar_info: pula linhas classificadas como "info" nas traduções
                      para reduzir ruído no pipeline seguinte.
    """

    def __init__(
        self,
        batch_size: int = BATCH_SIZE,
        ignorar_info: bool = False,
    ) -> None:
        self.batch_size = batch_size
        self.ignorar_info = ignorar_info

    def traduzir_arquivo(self, caminho_log: Path, plataforma: str = "desconhecida", tags_plataforma: list[str] = None) -> list[LogTraduzido]:
        """
        Lê o arquivo de log e retorna lista completa de LogTraduzido.
        
        Args:
            caminho_log: caminho do arquivo
            plataforma: plataforma detectada (linux, windows, macos, network, desconhecida)
            tags_plataforma: tags para otimizar buscas (ex: ["linux", "syslog"])
        """
        if not caminho_log.exists():
            raise FileNotFoundError(f"Arquivo de log não encontrado: {caminho_log}")

        if tags_plataforma is None:
            tags_plataforma = []

        with caminho_log.open(encoding="utf-8", errors="replace") as f:
            linhas_brutas = [l.rstrip("\n") for l in f.readlines()]

        # Remove linhas completamente vazias ou só whitespace
        linhas_indexadas = [
            (i + 1, linha)
            for i, linha in enumerate(linhas_brutas)
            if linha.strip()
        ]

        print(f"[*] Arquivo: {caminho_log.name} — {len(linhas_indexadas)} linhas úteis")
        return self._processar_em_lotes(linhas_indexadas, plataforma, tags_plataforma)

    def traduzir_texto(self, texto: str, plataforma: str = "desconhecida", tags_plataforma: list[str] = None) -> list[LogTraduzido]:
        """
        Traduz um bloco de texto de log diretamente (sem arquivo).
        
        Args:
            texto: texto dos logs
            plataforma: plataforma detectada
            tags_plataforma: tags para otimizar buscas
        """
        if tags_plataforma is None:
            tags_plataforma = []
        linhas = [(i + 1, l) for i, l in enumerate(texto.splitlines()) if l.strip()]
        return self._processar_em_lotes(linhas, plataforma, tags_plataforma)

    def traduzir_logs_filtrados(
        self,
        logs_filtrados: list,  # list[LogFiltrado] — evita import circular
        plataforma: str = "desconhecida",
        tags_plataforma: list[str] = None,
    ) -> list[LogTraduzido]:
        """
        Traduz apenas os logs que NÃO foram filtrados pelo AgenteFiltadorLogs (Stage 0).

        Usa os números de linha originais do arquivo, garantindo que o contexto
        de linha seja preservado no relatório final. Linhas marcadas como
        foi_filtrado=True são puladas — não consomem tokens do LLM e não
        chegam ao comparador de ameaças.

        Args:
            logs_filtrados: saída completa do AgenteFiltadorLogs.filtrar_arquivo()
            plataforma: plataforma detectada pelo Stage 0
            tags_plataforma: tags para otimizar buscas no Qdrant
        """
        if tags_plataforma is None:
            tags_plataforma = []

        # Mantém apenas linhas relevantes; preserva numero_linha original do arquivo
        linhas_relevantes = [
            (lf.numero_linha, lf.linha_original)
            for lf in logs_filtrados
            if not lf.foi_filtrado
        ]

        removidos = len(logs_filtrados) - len(linhas_relevantes)
        print(
            f"[*] Tradutor: {len(linhas_relevantes)} linhas relevantes "
            f"({removidos} ignoradas pelo filtrador)"
        )

        if not linhas_relevantes:
            print("[*] Nenhuma linha relevante para traduzir.")
            return []

        return self._processar_em_lotes(linhas_relevantes, plataforma, tags_plataforma)

    # ------------------------------------------------------------------
    # Processamento em lotes
    # ------------------------------------------------------------------
    def _processar_em_lotes(
        self, linhas_indexadas: list[tuple[int, str]], plataforma: str = "desconhecida", tags_plataforma: list[str] = None
    ) -> list[LogTraduzido]:
        if tags_plataforma is None:
            tags_plataforma = []
            
        todos_resultados: list[LogTraduzido] = []
        total_lotes = (len(linhas_indexadas) + self.batch_size - 1) // self.batch_size

        for i in range(0, len(linhas_indexadas), self.batch_size):
            lote = linhas_indexadas[i : i + self.batch_size]
            lote_num = i // self.batch_size + 1
            print(f"  [tradutor] Lote {lote_num}/{total_lotes} ({len(lote)} linhas)…")

            mapa_linhas = {num: linha for num, linha in lote}
            prompt = _build_prompt_traducao(lote)

            try:
                raw = _chamar_groq(prompt)
                resultados = _parsear_resposta(raw, mapa_linhas, plataforma, tags_plataforma)
            except (ValueError, RuntimeError) as exc:
                print(f"  [ERRO lote {lote_num}] {exc}", file=sys.stderr)
                # Fallback: cria entradas mínimas para não perder as linhas
                resultados = [
                    LogTraduzido(
                        linha_original=linha,
                        numero_linha=num,
                        descricao_comportamental=f"[tradução falhou] {linha}",
                        keywords_extraidas=[],
                        fonte_inferida="desconhecida",
                        severidade_inferida="info",
                        plataforma=plataforma,
                        tags_plataforma=tags_plataforma.copy(),
                    )
                    for num, linha in lote
                ]

            if self.ignorar_info:
                resultados = [r for r in resultados if r.severidade_inferida != "info"]

            todos_resultados.extend(resultados)

        return todos_resultados


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Traduz arquivo de log para descrições comportamentais.")
    parser.add_argument("arquivo", type=Path, help="Caminho para o arquivo de log.")
    parser.add_argument("--batch-size", type=int, default=BATCH_SIZE)
    parser.add_argument("--ignorar-info", action="store_true")
    parser.add_argument("--saida", type=Path, default=None, help="Salva resultado em JSON.")
    args = parser.parse_args()

    agente = AgenteTradutorLogs(batch_size=args.batch_size, ignorar_info=args.ignorar_info)
    traducoes = agente.traduzir_arquivo(args.arquivo)

    for t in traducoes:
        print(f"L{t.numero_linha} [{t.severidade_inferida.upper()}] {t.descricao_comportamental[:100]}")

    if args.saida:
        import dataclasses
        args.saida.write_text(
            json.dumps([dataclasses.asdict(t) for t in traducoes], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\n[+] Traduções salvas em: {args.saida}")