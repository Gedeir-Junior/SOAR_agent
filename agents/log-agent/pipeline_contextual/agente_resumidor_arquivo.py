"""
pipeline_contextual/agente_resumidor_arquivo.py

Stage 1 (map) do pipeline contextual.

Recebe as linhas relevantes de um arquivo de log (já filtradas pelo Stage 0 —
AgenteFiltadorLogs) e as divide em janelas de CONTEXTUAL_CHUNK_SIZE linhas.
Uma chamada ao LLM por janela produz um ResumoChunk com o comportamento
predominante do trecho, preservando os números de linha originais.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from services.groq_client import chamar_groq, extrair_json

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
CONTEXTUAL_CHUNK_SIZE = int(os.getenv("CONTEXTUAL_CHUNK_SIZE", "80"))

_SYSTEM_PROMPT = (
    "Você é um analista de segurança sênior especializado em análise de logs. "
    "Sua tarefa é resumir o comportamento predominante de um trecho de log, "
    "capturando a intenção geral em vez de descrever cada linha isoladamente — "
    "mas SEM abstrair os artefatos técnicos literais (comandos, IDs de evento, "
    "nomes de binário/processo), pois esse resumo alimenta uma busca semântica "
    "que depende desses termos para encontrar a técnica MITRE correta. "
    "Responda SOMENTE com JSON válido, sem markdown nem explicações."
)


# ---------------------------------------------------------------------------
# Dataclass de saída
# ---------------------------------------------------------------------------
@dataclass
class ResumoChunk:
    numero_chunk: int
    linha_inicio: int
    linha_fim: int
    resumo_comportamental: str
    entidades_identificadas: list[str] = field(default_factory=list)
    severidade_maxima: str = "info"


# ---------------------------------------------------------------------------
# Construção e parsing do prompt
# ---------------------------------------------------------------------------
def _build_prompt_resumo(linhas: list[tuple[int, str]]) -> str:
    bloco = "\n".join(f"{num}: {linha}" for num, linha in linhas)
    return f"""Analise o trecho de log abaixo (linhas {linhas[0][0]} a {linhas[-1][0]}) e retorne um JSON com a estrutura:

{{
  "resumo_comportamental": "<2-4 frases descrevendo o comportamento predominante do trecho: o que está acontecendo, quem está envolvido (usuário/processo/IP/host), e por que é relevante para segurança — incluindo VERBATIM os comandos, IDs de evento e nomes de binário/processo mais relevantes do trecho (ex: citar 'sc.exe query type= service', 'Event ID 4688', não apenas parafrasear como 'enumeração de serviços')>",
  "entidades_identificadas": ["<IP, usuário, processo, host ou outro identificador notável>"],
  "severidade_maxima": "<info | low | medium | high | critical>"
}}

Critérios:
- resumo_comportamental deve capturar o padrão geral do trecho, sem repetir linha a linha, mas preservando literalmente (não parafraseando) os comandos, IDs de evento e nomes de binário/processo que aparecem no trecho.
- severidade_maxima é a maior severidade observada em qualquer linha do trecho.
- Nunca invente entidades ou eventos que não aparecem no trecho.

Trecho de log:
{bloco}
"""


def _parsear_resposta(raw: str, numero_chunk: int, linha_inicio: int, linha_fim: int) -> ResumoChunk:
    data = json.loads(extrair_json(raw))
    return ResumoChunk(
        numero_chunk=numero_chunk,
        linha_inicio=linha_inicio,
        linha_fim=linha_fim,
        resumo_comportamental=data.get("resumo_comportamental", ""),
        entidades_identificadas=data.get("entidades_identificadas", []),
        severidade_maxima=data.get("severidade_maxima", "info"),
    )


# ---------------------------------------------------------------------------
# Agente principal
# ---------------------------------------------------------------------------
class AgenteResumidorArquivo:
    """
    Stage 1 (map) do pipeline contextual: divide as linhas relevantes em
    janelas de `chunk_size` linhas e gera um ResumoChunk por chamada ao LLM.
    """

    def __init__(self, chunk_size: int = CONTEXTUAL_CHUNK_SIZE) -> None:
        self.chunk_size = chunk_size

    def resumir_logs_filtrados(self, logs_filtrados: list) -> list[ResumoChunk]:
        """
        Recebe a saída completa do AgenteFiltadorLogs (Stage 0) e resume apenas
        as linhas não filtradas, preservando os números de linha originais do
        arquivo.
        """
        linhas_relevantes = [
            (lf.numero_linha, lf.linha_original)
            for lf in logs_filtrados
            if not lf.foi_filtrado
        ]
        removidos = len(logs_filtrados) - len(linhas_relevantes)
        print(
            f"[*] Resumidor: {len(linhas_relevantes)} linhas relevantes "
            f"({removidos} ignoradas pelo filtrador)"
        )
        return self.resumir_linhas(linhas_relevantes)

    def resumir_arquivo(self, caminho_log: Path) -> list[ResumoChunk]:
        """Lê o arquivo diretamente e resume, sem passar pelo Stage 0."""
        if not caminho_log.exists():
            raise FileNotFoundError(f"Arquivo de log não encontrado: {caminho_log}")

        with caminho_log.open(encoding="utf-8", errors="replace") as f:
            linhas_brutas = [l.rstrip("\n") for l in f.readlines()]

        linhas_indexadas = [
            (i + 1, linha)
            for i, linha in enumerate(linhas_brutas)
            if linha.strip()
        ]
        print(f"[*] Resumidor: {caminho_log.name} — {len(linhas_indexadas)} linhas úteis")
        return self.resumir_linhas(linhas_indexadas)

    def resumir_linhas(self, linhas_indexadas: list[tuple[int, str]]) -> list[ResumoChunk]:
        if not linhas_indexadas:
            print("[*] Nenhuma linha relevante para resumir.")
            return []

        resumos: list[ResumoChunk] = []
        total_chunks = (len(linhas_indexadas) + self.chunk_size - 1) // self.chunk_size

        for i in range(0, len(linhas_indexadas), self.chunk_size):
            lote = linhas_indexadas[i : i + self.chunk_size]
            numero_chunk = i // self.chunk_size + 1
            linha_inicio = lote[0][0]
            linha_fim = lote[-1][0]
            print(f"  [resumidor] Chunk {numero_chunk}/{total_chunks} (linhas {linha_inicio}-{linha_fim})…")

            try:
                raw = chamar_groq(
                    _build_prompt_resumo(lote),
                    _SYSTEM_PROMPT,
                    temperature=0.1,
                    origem="resumidor",
                )
                resumo = _parsear_resposta(raw, numero_chunk, linha_inicio, linha_fim)
            except Exception as exc:
                print(f"  [ERRO chunk {numero_chunk}] {exc}", file=sys.stderr)
                resumo = ResumoChunk(
                    numero_chunk=numero_chunk,
                    linha_inicio=linha_inicio,
                    linha_fim=linha_fim,
                    resumo_comportamental=f"[resumo falhou] trecho entre linhas {linha_inicio}-{linha_fim}",
                    entidades_identificadas=[],
                    severidade_maxima="info",
                )

            resumos.append(resumo)

        return resumos


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    import dataclasses

    parser = argparse.ArgumentParser(description="Resume um arquivo de log em chunks comportamentais.")
    parser.add_argument("arquivo", type=Path, help="Caminho para o arquivo de log.")
    parser.add_argument("--chunk-size", type=int, default=CONTEXTUAL_CHUNK_SIZE)
    parser.add_argument("--saida", type=Path, default=None, help="Salva resultado em JSON.")
    args = parser.parse_args()

    agente = AgenteResumidorArquivo(chunk_size=args.chunk_size)
    resumos = agente.resumir_arquivo(args.arquivo)

    for r in resumos:
        print(f"Chunk {r.numero_chunk} (L{r.linha_inicio}-{r.linha_fim}) [{r.severidade_maxima.upper()}] {r.resumo_comportamental[:100]}")

    if args.saida:
        args.saida.write_text(
            json.dumps([dataclasses.asdict(r) for r in resumos], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\n[+] Resumos salvos em: {args.saida}")
