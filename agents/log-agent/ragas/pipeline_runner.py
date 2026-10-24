"""
ragas/pipeline_runner.py

Executa o pipeline de produção (Filtrador -> Tradutor -> Comparador) sobre um
arquivo de log, exatamente como o endpoint /analyze faz em main.py.

Usado pelo construtor_dataset.py para gerar o dataset de avaliação SEM
reimplementar (e potencialmente enviesar) a lógica de detecção — o mesmo
código que roda em produção é o código avaliado.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from pipeline.agente_filtrador_logs import AgenteFiltadorLogs, LogFiltrado
from pipeline.agente_tradutor_logs import AgenteTradutorLogs, LogTraduzido
from pipeline.agent_comparador_ameacas import AgenteComparadorAmeacas, RelatorioAmeacas


@dataclass
class ResultadoPipeline:
    """Saída completa das três etapas do pipeline real para um arquivo de log."""
    arquivo: str
    plataforma_detectada: str
    logs_filtrados: list[LogFiltrado]
    traducoes: list[LogTraduzido]
    relatorio: RelatorioAmeacas


def executar_pipeline_real(
    caminho_log: Path,
    *,
    batch_size: int = 15,
    top_k: int = 3,
    limiar_score: float = 0.40,
    gerar_analise_llm: bool = False,
) -> ResultadoPipeline:
    """
    Executa Stage 0 (filtragem + detecção de plataforma), Stage 1 (tradução)
    e Stage 2 (comparação com Qdrant) sobre `caminho_log`, na mesma sequência
    usada por `_processar_arquivo_logs` em main.py.

    `gerar_analise_llm=False` por padrão: a síntese textual por ameaça não é
    necessária para as métricas de avaliação e evita chamadas extras ao LLM.
    """
    # --- Stage 0: filtragem + detecção de plataforma ---
    filtrador = AgenteFiltadorLogs()
    logs_filtrados, plataforma = filtrador.filtrar_arquivo(caminho_log)

    tags_plataforma = logs_filtrados[0].tags_plataforma if logs_filtrados else []

    # --- Stage 1: tradução comportamental ---
    tradutor = AgenteTradutorLogs(batch_size=batch_size)
    traducoes = tradutor.traduzir_logs_filtrados(
        logs_filtrados=logs_filtrados,
        plataforma=plataforma,
        tags_plataforma=tags_plataforma,
    )

    # --- Stage 2: comparação semântica/lexical com o banco MITRE (Qdrant) ---
    comparador = AgenteComparadorAmeacas(
        top_k=top_k,
        limiar_score=limiar_score,
        gerar_analise_llm=gerar_analise_llm,
    )
    relatorio = comparador.analisar(traducoes, nome_arquivo_log=caminho_log.name)

    return ResultadoPipeline(
        arquivo=caminho_log.name,
        plataforma_detectada=plataforma,
        logs_filtrados=logs_filtrados,
        traducoes=traducoes,
        relatorio=relatorio,
    )
