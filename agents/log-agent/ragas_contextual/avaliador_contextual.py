"""
ragas_contextual/avaliador_contextual.py

Calcula as métricas RAGAS do pipeline_contextual a partir do dataset gerado
por construtor_dataset_contextual.py.

Quatro eixos de avaliação:

  1. Context Precision — das técnicas MITRE recuperadas por fase, quantas são
     de fato as esperadas pelo gabarito? (determinístico, sem juiz LLM)
  2. Context Recall    — das técnicas esperadas pelo gabarito, quantas o
     retriever de fato recuperou? (determinístico, sem juiz LLM)
  3. Faithfulness      — a narrativa/resumo/análise por ameaça geradas pelo
     LLM são sustentadas pelo contexto recuperado, sem alucinar? (juiz Groq)
  4. Answer Relevancy   — essas respostas geradas respondem de fato à pergunta
     (não são genéricas/fora do assunto)? (juiz Groq + embeddings locais)

Mais um check estrutural (não é métrica RAGAS, mas é o que valida a "trava de
segurança" do organizador de fases): total_fases bate com o gabarito e as
fases não se sobrepõem / não saem de ordem.

Uso:
    python ragas_contextual/gerador_logs_multifase.py       # gera cenários
    python ragas_contextual/construtor_dataset_contextual.py # gera dataset
    python ragas_contextual/avaliador_contextual.py           # avalia

    # ou em um único passo:
    python ragas_contextual/avaliador_contextual.py --pipeline-completo
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

DIR_CENARIOS_PADRAO = Path("./ragas_contextual/resultados")
DATASET_PADRAO = Path("./ragas_contextual/resultados/dataset_contextual.json")
SAIDA_PADRAO = Path("./ragas_contextual/resultados/metricas_contextual.json")


# ---------------------------------------------------------------------------
# Métricas — 1) e 2) Context Precision / Context Recall (por fase)
# ---------------------------------------------------------------------------
def calcular_metricas_contexto(amostras: list[dict]) -> dict:
    precisao_por_amostra: list[float] = []
    recall_por_amostra: list[float] = []
    soma_inter = soma_recuperadas = soma_esperadas = 0
    detalhes = []

    for a in amostras:
        esperadas = set(a["tecnicas_esperadas"])
        recuperadas = {t["tecnica_id"] for t in a["tecnicas_recuperadas"]}
        inter = esperadas & recuperadas

        precisao = round(len(inter) / len(recuperadas), 4) if recuperadas else None
        recall = round(len(inter) / len(esperadas), 4) if esperadas else None

        if precisao is not None:
            precisao_por_amostra.append(precisao)
        if recall is not None:
            recall_por_amostra.append(recall)

        soma_inter += len(inter)
        soma_recuperadas += len(recuperadas)
        soma_esperadas += len(esperadas)

        detalhes.append({
            "arquivo": a["arquivo"],
            "fase": a["numero_fase_esperado"],
            "tatica": a["tatica_esperada"],
            "esperadas": sorted(esperadas),
            "recuperadas": sorted(recuperadas),
            "precisao": precisao,
            "recall": recall,
        })

    return {
        "total_fases": len(amostras),
        "context_precision_macro": _media(precisao_por_amostra),
        "context_recall_macro": _media(recall_por_amostra),
        "context_precision_micro": round(soma_inter / soma_recuperadas, 4) if soma_recuperadas else None,
        "context_recall_micro": round(soma_inter / soma_esperadas, 4) if soma_esperadas else None,
        "detalhes": detalhes,
    }


# ---------------------------------------------------------------------------
# Métricas — 3) e 4) Faithfulness / Answer Relevancy (juiz Groq) + ordem
# ---------------------------------------------------------------------------
def calcular_metricas_geracao(
    amostras_documento: list[dict],
    amostras_ameaca: list[dict],
    avaliar_ordem: bool = True,
) -> dict:
    from ragas_contextual.juiz_llm import (
        avaliar_answer_relevancy,
        avaliar_faithfulness,
        avaliar_ordem_narrativa,
    )

    faithfulness_scores: list[float] = []
    relevancy_scores: list[float] = []
    ordem_resultados: list[bool] = []
    detalhes_documento = []

    for doc in amostras_documento:
        contexto = doc["contexto"]
        pergunta = doc["pergunta"]
        entrada = {"arquivo": doc["arquivo"]}

        for campo in ("resposta_narrativa", "resposta_resumo"):
            resposta = doc.get(campo, "")
            if not resposta.strip():
                continue
            print(f"  [juiz] {doc['arquivo']} :: {campo} — faithfulness…")
            f = avaliar_faithfulness(resposta, contexto)
            print(f"  [juiz] {doc['arquivo']} :: {campo} — answer relevancy…")
            r = avaliar_answer_relevancy(pergunta, resposta)
            if f.score is not None:
                faithfulness_scores.append(f.score)
            if r.score is not None:
                relevancy_scores.append(r.score)
            entrada[campo] = {"faithfulness": f.score, "answer_relevancy": r.score, "erro_faithfulness": f.erro, "erro_relevancy": r.erro}

        if avaliar_ordem:
            print(f"  [juiz] {doc['arquivo']} :: ordem cronológica da narrativa…")
            ordem = avaliar_ordem_narrativa(doc.get("resposta_narrativa", ""), doc.get("titulos_fases_em_ordem", []))
            entrada["ordem_narrativa_correta"] = ordem.ordem_correta
            entrada["ordem_narrativa_justificativa"] = ordem.justificativa
            if ordem.ordem_correta is not None:
                ordem_resultados.append(ordem.ordem_correta)

        detalhes_documento.append(entrada)

    detalhes_ameaca = []
    for am in amostras_ameaca:
        print(f"  [juiz] {am['arquivo']} :: ameaça {am['tecnica_id']} — faithfulness/relevancy…")
        f = avaliar_faithfulness(am["resposta"], am["contexto"])
        r = avaliar_answer_relevancy(am["pergunta"], am["resposta"])
        if f.score is not None:
            faithfulness_scores.append(f.score)
        if r.score is not None:
            relevancy_scores.append(r.score)
        detalhes_ameaca.append({
            "arquivo": am["arquivo"],
            "tecnica_id": am["tecnica_id"],
            "faithfulness": f.score,
            "answer_relevancy": r.score,
        })

    return {
        "faithfulness_medio": _media(faithfulness_scores),
        "answer_relevancy_medio": _media(relevancy_scores),
        "taxa_ordem_narrativa_correta": round(sum(ordem_resultados) / len(ordem_resultados), 4) if ordem_resultados else None,
        "total_avaliacoes_faithfulness": len(faithfulness_scores),
        "total_avaliacoes_relevancy": len(relevancy_scores),
        "detalhes_documento": detalhes_documento,
        "detalhes_ameaca": detalhes_ameaca,
    }


# ---------------------------------------------------------------------------
# Checks estruturais (determinísticos)
# ---------------------------------------------------------------------------
def calcular_checks_estruturais(checks: list[dict]) -> dict:
    total = len(checks)
    ok_ordem = sum(1 for c in checks if c["fases_ordenadas_sem_sobreposicao"])
    ok_contagem = sum(1 for c in checks if c["total_fases_esperado"] == c["total_fases_detectado"])
    return {
        "total_arquivos": total,
        "taxa_fases_sem_sobreposicao": round(ok_ordem / total, 4) if total else None,
        "taxa_total_fases_bate_gabarito": round(ok_contagem / total, 4) if total else None,
        "detalhes": checks,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _media(valores: list[float]) -> Optional[float]:
    return round(sum(valores) / len(valores), 4) if valores else None


def _barra(taxa: float, largura: int = 20) -> str:
    cheios = int(round(taxa * largura))
    return "█" * cheios + "░" * (largura - cheios)


def _fmt_pct(valor: Optional[float]) -> str:
    return f"{valor:.1%}" if valor is not None else "N/A"


# ---------------------------------------------------------------------------
# Relatório
# ---------------------------------------------------------------------------
def imprimir_relatorio(m_contexto: dict, m_geracao: Optional[dict], m_estrutural: dict) -> None:
    print("\n" + "=" * 64)
    print("  RELATÓRIO DE AVALIAÇÃO RAGAS — Pipeline Contextual (por fases)")
    print("=" * 64)

    print("\n[Context Precision / Recall] Busca semântica pura por fase")
    print(f"  Total de fases avaliadas : {m_contexto['total_fases']}")
    print(f"  Context Precision (macro): {_barra(m_contexto['context_precision_macro'] or 0)} {_fmt_pct(m_contexto['context_precision_macro'])}")
    print(f"  Context Recall    (macro): {_barra(m_contexto['context_recall_macro'] or 0)} {_fmt_pct(m_contexto['context_recall_macro'])}")
    print(f"  Context Precision (micro): {_fmt_pct(m_contexto['context_precision_micro'])}")
    print(f"  Context Recall    (micro): {_fmt_pct(m_contexto['context_recall_micro'])}")

    print("\n  Detalhe por fase:")
    for d in m_contexto["detalhes"]:
        print(
            f"    [{d['arquivo']:<28}] Fase {d['fase']} ({d['tatica']:<22}) "
            f"P={_fmt_pct(d['precisao']):<6} R={_fmt_pct(d['recall']):<6} "
            f"esperadas={d['esperadas']} recuperadas={d['recuperadas']}"
        )

    if m_geracao is not None:
        print("\n[Faithfulness / Answer Relevancy] Textos gerados pelo LLM (juiz Groq)")
        print(f"  Faithfulness médio      : {_barra(m_geracao['faithfulness_medio'] or 0)} {_fmt_pct(m_geracao['faithfulness_medio'])} "
              f"({m_geracao['total_avaliacoes_faithfulness']} avaliação(ões))")
        print(f"  Answer Relevancy médio  : {_barra(m_geracao['answer_relevancy_medio'] or 0)} {_fmt_pct(m_geracao['answer_relevancy_medio'])} "
              f"({m_geracao['total_avaliacoes_relevancy']} avaliação(ões))")
        print(f"  Ordem cronológica correta: {_fmt_pct(m_geracao['taxa_ordem_narrativa_correta'])}")
    else:
        print("\n[Faithfulness / Answer Relevancy] PULADO (--pular-juiz-llm)")

    print("\n[Checks estruturais] Trava de recálculo de linhas do organizador de fases")
    print(f"  Fases sem sobreposição/fora de ordem: {_fmt_pct(m_estrutural['taxa_fases_sem_sobreposicao'])}")
    print(f"  total_fases bate com o gabarito     : {_fmt_pct(m_estrutural['taxa_total_fases_bate_gabarito'])}")
    for d in m_estrutural["detalhes"]:
        marca = "OK " if d["fases_ordenadas_sem_sobreposicao"] and d["total_fases_esperado"] == d["total_fases_detectado"] else "AVISO"
        print(
            f"    [{marca}] {d['arquivo']:<28} fases esperadas={d['total_fases_esperado']} "
            f"detectadas={d['total_fases_detectado']}"
        )
        for problema in d["problemas_ordem"]:
            print(f"        - {problema}")

    print("\n" + "=" * 64)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Avalia o pipeline contextual real (por fases) com métricas RAGAS."
    )
    parser.add_argument("--dataset", type=Path, default=DATASET_PADRAO)
    parser.add_argument("--saida", type=Path, default=SAIDA_PADRAO)
    parser.add_argument("--pipeline-completo", action="store_true",
                         help="Executa o pipeline real (construtor_dataset_contextual) antes de avaliar")
    parser.add_argument("--dir-cenarios", type=Path, default=DIR_CENARIOS_PADRAO)
    parser.add_argument("--chunk-size", type=int, default=80)
    parser.add_argument("--reduce-batch-size", type=int, default=20)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--limiar-score", type=float, default=0.45)
    parser.add_argument("--sem-analise-llm", action="store_true",
                         help="Pula a análise LLM por ameaça ao construir o dataset (mais rápido).")
    parser.add_argument("--pular-juiz-llm", action="store_true",
                         help="Pula Faithfulness/Answer Relevancy/ordem (só Context Precision/Recall + estrutural).")
    args = parser.parse_args()

    if args.pipeline_completo:
        from ragas_contextual.construtor_dataset_contextual import ConstrutorDatasetContextual

        construtor = ConstrutorDatasetContextual(
            dir_cenarios=args.dir_cenarios,
            chunk_size=args.chunk_size,
            reduce_batch_size=args.reduce_batch_size,
            top_k=args.top_k,
            limiar_score=args.limiar_score,
            gerar_analise_llm=not args.sem_analise_llm,
        )
        dataset = construtor.construir()
        args.dataset.parent.mkdir(parents=True, exist_ok=True)
        args.dataset.write_text(json.dumps(dataset, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n[✓] Dataset de avaliação contextual salvo: {args.dataset}")
    else:
        if not args.dataset.exists():
            print(f"[!] Dataset não encontrado: {args.dataset}")
            print("    Execute primeiro: python ragas_contextual/construtor_dataset_contextual.py")
            sys.exit(1)
        dataset = json.loads(args.dataset.read_text(encoding="utf-8"))

    print(
        f"\n[*] Dataset carregado: {len(dataset['amostras_contexto'])} amostras de contexto, "
        f"{len(dataset['amostras_geracao_documento'])} documento(s), "
        f"{len(dataset['amostras_geracao_ameaca'])} amostra(s) de ameaça"
    )

    m_contexto = calcular_metricas_contexto(dataset["amostras_contexto"])
    m_estrutural = calcular_checks_estruturais(dataset["checks_estruturais"])

    m_geracao = None
    if not args.pular_juiz_llm:
        m_geracao = calcular_metricas_geracao(
            dataset["amostras_geracao_documento"], dataset["amostras_geracao_ameaca"]
        )

    imprimir_relatorio(m_contexto, m_geracao, m_estrutural)

    resultados = {
        "dataset_path": str(args.dataset),
        "resumo_plataformas": dataset.get("resumo_plataformas", []),
        "contexto": m_contexto,
        "geracao": m_geracao,
        "estrutural": m_estrutural,
    }
    args.saida.parent.mkdir(parents=True, exist_ok=True)
    args.saida.write_text(json.dumps(resultados, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[✓] Resultados salvos em: {args.saida}")


if __name__ == "__main__":
    main()
