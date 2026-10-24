"""
ragas_contextual/pipeline_runner_contextual.py

Executa o pipeline contextual de produção (Filtrador -> Resumidor -> Organizador
de Fases -> Comparador Contextual) sobre um arquivo de log, exatamente como o
endpoint POST /analyze-contextual faz em main.py — nenhuma lógica de detecção é
reimplementada aqui, o mesmo código avaliado é o que roda em produção (mesmo
espírito de ragas/pipeline_runner.py para o pipeline linha-a-linha).

Diferença chave em relação ao pipeline linha-a-linha: além do RelatorioContextual
final (que já aplica filtro de plataforma e agrupa por técnica), também expomos
os candidatos BRUTOS da busca semântica por fase — é isso que
construtor_dataset_contextual.py usa para medir Context Precision/Recall contra
o gabarito, já que o RelatorioContextual final não preserva "o que foi
recuperado mas descartado" por fase.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from pipeline.agente_filtrador_logs import AgenteFiltadorLogs
from pipeline_contextual.agente_comparador_contextual import (
    AgenteComparadorContextual,
    RelatorioContextual,
)
from pipeline_contextual.agente_organizador_fases import (
    AgenteOrganizadorFases,
    FaseComportamental,
)
from pipeline_contextual.agente_resumidor_arquivo import AgenteResumidorArquivo
from retriever.semantic_retriever import ResultadoBusca, RetrieverSemantico


@dataclass
class ResultadoPipelineContextual:
    """Saída completa do pipeline contextual para um arquivo de log, incluindo
    os candidatos brutos de busca semântica por fase (pré-filtro de plataforma)."""
    arquivo: str
    plataforma_detectada: str
    total_linhas_analisadas: int
    fases: list[FaseComportamental]
    candidatos_por_fase: dict[int, list[ResultadoBusca]] = field(default_factory=dict)
    relatorio: RelatorioContextual = None


def executar_pipeline_contextual_real(
    caminho_log: Path,
    *,
    chunk_size: int = 80,
    reduce_batch_size: int = 20,
    top_k: int = 5,
    limiar_score: float = 0.45,
    gerar_analise_llm: bool = False,
) -> ResultadoPipelineContextual:
    """
    Executa Stage 0 (filtragem + plataforma), Stage 1 (resumo em chunks),
    Stage 2 (organização em fases) e Stage 3 (comparação semântica pura +
    síntese narrativa), na mesma sequência usada por
    `_processar_arquivo_contextual` em main.py.

    `gerar_analise_llm=False` por padrão: a análise textual por ameaça não é
    necessária para as métricas de contexto (Precision/Recall) e evita
    chamadas extras ao Groq — ligue quando for avaliar Faithfulness/Answer
    Relevancy da síntese textual.
    """
    # --- Stage 0: filtragem + detecção de plataforma ---
    filtrador = AgenteFiltadorLogs()
    logs_filtrados, plataforma = filtrador.filtrar_arquivo(caminho_log)

    # --- Stage 1 (map): resumo por chunk ---
    resumidor = AgenteResumidorArquivo(chunk_size=chunk_size)
    resumos = resumidor.resumir_logs_filtrados(logs_filtrados)

    # --- Stage 2 (reduce): consolidação em fases comportamentais ---
    organizador = AgenteOrganizadorFases(reduce_batch_size=reduce_batch_size)
    fases = organizador.organizar(resumos)

    # --- Contexto bruto por fase (para métricas de Context Precision/Recall) ---
    # Busca a mesma query que o comparador usaria, mas SEM aplicar o filtro de
    # plataforma incompatível — queremos ver tudo que o retriever considerou
    # relevante antes de qualquer descarte downstream. Une candidatos do
    # resumo comportamental com candidatos do texto bruto das linhas da fase
    # (mesma lógica de `AgenteComparadorContextual.analisar`, ver achado de
    # 15/08/2026 sobre recall de Initial Access).
    retriever = RetrieverSemantico(top_k=top_k, limiar_score=limiar_score)
    logs_por_linha = {
        lf.numero_linha: lf.linha_original for lf in logs_filtrados if not lf.foi_filtrado
    }
    candidatos_por_fase: dict[int, list[ResultadoBusca]] = {}
    for fase in fases:
        candidatos: dict[str, ResultadoBusca] = {
            r.tecnica_id: r
            for r in retriever.buscar(
                query=fase.descricao_comportamental,
                top_k=top_k,
                limiar_score=limiar_score,
            )
        }
        trecho_bruto = "\n".join(
            logs_por_linha[n]
            for n in range(fase.linha_inicio, fase.linha_fim + 1)
            if n in logs_por_linha
        )
        if trecho_bruto.strip():
            for r in retriever.buscar(query=trecho_bruto, top_k=top_k, limiar_score=limiar_score):
                existente = candidatos.get(r.tecnica_id)
                if existente is None or r.score > existente.score:
                    candidatos[r.tecnica_id] = r
        candidatos_por_fase[fase.numero_fase] = sorted(
            candidatos.values(), key=lambda r: r.score, reverse=True
        )

    # --- Stage 3: comparação semântica pura + síntese narrativa ---
    comparador = AgenteComparadorContextual(
        top_k=top_k,
        limiar_score=limiar_score,
        gerar_analise_llm=gerar_analise_llm,
    )
    relatorio = comparador.analisar(
        fases,
        nome_arquivo_log=caminho_log.name,
        plataforma_predominante=plataforma,
        total_linhas_analisadas=len(logs_filtrados),
        logs_filtrados=logs_filtrados,
    )

    return ResultadoPipelineContextual(
        arquivo=caminho_log.name,
        plataforma_detectada=plataforma,
        total_linhas_analisadas=len(logs_filtrados),
        fases=fases,
        candidatos_por_fase=candidatos_por_fase,
        relatorio=relatorio,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    import dataclasses
    import json

    parser = argparse.ArgumentParser(
        description="Executa o pipeline contextual real sobre um arquivo de log."
    )
    parser.add_argument("arquivo", type=Path)
    parser.add_argument("--chunk-size", type=int, default=80)
    parser.add_argument("--reduce-batch-size", type=int, default=20)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--limiar-score", type=float, default=0.45)
    parser.add_argument("--analise-llm", action="store_true")
    parser.add_argument("--saida", type=Path, default=None)
    args = parser.parse_args()

    resultado = executar_pipeline_contextual_real(
        args.arquivo,
        chunk_size=args.chunk_size,
        reduce_batch_size=args.reduce_batch_size,
        top_k=args.top_k,
        limiar_score=args.limiar_score,
        gerar_analise_llm=args.analise_llm,
    )

    print(f"\n[+] Plataforma detectada: {resultado.plataforma_detectada}")
    print(f"[+] Fases identificadas: {len(resultado.fases)}")
    for fase in resultado.fases:
        candidatos = resultado.candidatos_por_fase.get(fase.numero_fase, [])
        tecnicas = ", ".join(c.tecnica_id for c in candidatos) or "nenhuma"
        print(f"  Fase {fase.numero_fase} (L{fase.linha_inicio}-{fase.linha_fim}): {fase.titulo_fase} | candidatos: {tecnicas}")

    if args.saida:
        args.saida.write_text(
            json.dumps({
                "arquivo": resultado.arquivo,
                "plataforma_detectada": resultado.plataforma_detectada,
                "total_linhas_analisadas": resultado.total_linhas_analisadas,
                "fases": [dataclasses.asdict(f) for f in resultado.fases],
                "candidatos_por_fase": {
                    str(k): [dataclasses.asdict(c) for c in v]
                    for k, v in resultado.candidatos_por_fase.items()
                },
                "relatorio": dataclasses.asdict(resultado.relatorio),
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\n[+] Resultado salvo em: {args.saida}")
