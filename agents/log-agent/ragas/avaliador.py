"""
ragas/avaliador.py

Calcula métricas de avaliação do pipeline real de detecção de ameaças a
partir do dataset gerado por construtor_dataset.py.

Três eixos de avaliação, sem depender de LLM externo como "juiz":

  1. Plataforma  — o AgenteFiltadorLogs (Stage 0) identificou a plataforma
                    correta (linux | windows | macos | network)?
  2. Classificação de ameaça — o pipeline (Stage 1+2) classificou cada linha
                    como ameaça/não-ameaça de acordo com o gabarito
                    (ameaca | benigna | falso_positivo)?
  3. Técnica MITRE — quando a linha é uma ameaça real, o pipeline apontou a
                    técnica MITRE correta?

Uso:
    python ragas/construtor_dataset.py          # gera dataset_avaliacao.json
    python ragas/avaliador.py                    # avalia o dataset gerado

    # ou em um único passo:
    python ragas/avaliador.py --pipeline-completo
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
DIR_LOGS_SINTETICOS_PADRAO = Path("./ragas/resultados")
DATASET_PADRAO = Path("./ragas/resultados/dataset_avaliacao.json")
SAIDA_PADRAO = Path("./ragas/resultados/metricas_avaliacao.json")


# ---------------------------------------------------------------------------
# Métricas — 1) Detecção de plataforma (Stage 0)
# ---------------------------------------------------------------------------
def calcular_metricas_plataforma(resumo_plataformas: list[dict]) -> dict:
    total = len(resumo_plataformas)
    acertos = sum(1 for r in resumo_plataformas if r["plataforma_correta"])
    return {
        "total_arquivos": total,
        "acertos": acertos,
        "accuracy": round(acertos / total, 4) if total else None,
        "detalhes": resumo_plataformas,
    }


# ---------------------------------------------------------------------------
# Métricas — 2) Classificação ameaça vs benigna/falso-positivo (Stage 1+2)
# ---------------------------------------------------------------------------
def calcular_metricas_classificacao_ameaca(amostras: list[dict]) -> dict:
    tp = fp = fn = tn = 0
    contagem_por_tipo: dict[str, dict[str, int]] = {}

    for a in amostras:
        esperado = a["e_ameaca_esperada"]
        detectado = a["e_ameaca_detectada"]
        tipo = a["tipo_esperado"]

        c = contagem_por_tipo.setdefault(tipo, {"acertos": 0, "total": 0})
        c["total"] += 1
        if esperado == detectado:
            c["acertos"] += 1

        if esperado and detectado:
            tp += 1
        elif esperado and not detectado:
            fn += 1
        elif not esperado and detectado:
            fp += 1
        else:
            tn += 1

    total = tp + fp + fn + tn
    precisao = round(tp / (tp + fp), 4) if (tp + fp) else None
    recall = round(tp / (tp + fn), 4) if (tp + fn) else None
    f1 = (
        round(2 * precisao * recall / (precisao + recall), 4)
        if precisao and recall and (precisao + recall) > 0
        else None
    )
    accuracy = round((tp + tn) / total, 4) if total else None

    taxa_por_tipo = {
        tipo: round(c["acertos"] / c["total"], 4)
        for tipo, c in contagem_por_tipo.items()
    }

    return {
        "total_amostras": total,
        "matriz_confusao": {
            "verdadeiro_positivo": tp,
            "falso_positivo": fp,
            "falso_negativo": fn,
            "verdadeiro_negativo": tn,
        },
        "precisao": precisao,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "taxa_acerto_classificacao_por_tipo": taxa_por_tipo,
    }


# ---------------------------------------------------------------------------
# Métricas — 3) Técnica MITRE correta (apenas amostras "ameaca")
# ---------------------------------------------------------------------------
def calcular_metricas_tecnica(amostras: list[dict]) -> dict:
    ameacas = [a for a in amostras if a["tipo_esperado"] == "ameaca"]
    total = len(ameacas)
    if total == 0:
        return {"total_ameacas": 0}

    detectadas = 0
    tecnica_correta = 0
    distribuicao_estagio_perda: dict[str, int] = {}
    por_tatica: dict[str, dict[str, int]] = {}

    for a in ameacas:
        tatica = a.get("tatica_esperada") or "Desconhecida"
        bucket = por_tatica.setdefault(
            tatica, {"total": 0, "detectadas": 0, "tecnica_correta": 0}
        )
        bucket["total"] += 1

        if a["e_ameaca_detectada"]:
            detectadas += 1
            bucket["detectadas"] += 1
            if a["tecnica_esperada"] and a["tecnica_esperada"] in (a["tecnicas_detectadas"] or []):
                tecnica_correta += 1
                bucket["tecnica_correta"] += 1
        else:
            estagio = a.get("estagio_perda") or "desconhecido"
            distribuicao_estagio_perda[estagio] = distribuicao_estagio_perda.get(estagio, 0) + 1

    taxa_por_tatica = {
        t: {
            "total": v["total"],
            "taxa_deteccao": round(v["detectadas"] / v["total"], 4),
            "taxa_tecnica_correta": round(v["tecnica_correta"] / v["total"], 4),
        }
        for t, v in sorted(por_tatica.items())
    }

    return {
        "total_ameacas": total,
        "total_detectadas": detectadas,
        "total_tecnica_correta": tecnica_correta,
        "taxa_deteccao": round(detectadas / total, 4),
        "taxa_tecnica_correta_dado_detectado": (
            round(tecnica_correta / detectadas, 4) if detectadas else None
        ),
        "taxa_tecnica_correta_geral": round(tecnica_correta / total, 4),
        "distribuicao_estagio_perda": distribuicao_estagio_perda,
        "taxa_por_tatica": taxa_por_tatica,
    }


# ---------------------------------------------------------------------------
# Relatório
# ---------------------------------------------------------------------------
def _barra(taxa: float, largura: int = 20) -> str:
    cheios = int(round(taxa * largura))
    return "█" * cheios + "░" * (largura - cheios)


def _fmt_pct(valor: Optional[float]) -> str:
    return f"{valor:.1%}" if valor is not None else "N/A"


def imprimir_relatorio(m_plataforma: dict, m_classificacao: dict, m_tecnica: dict) -> None:
    print("\n" + "=" * 64)
    print("  RELATÓRIO DE AVALIAÇÃO — Pipeline Real de Detecção de Ameaças")
    print("=" * 64)

    # --- Plataforma ---
    print("\n[Plataforma] Detecção de plataforma (Stage 0)")
    print(f"  Accuracy: {_fmt_pct(m_plataforma['accuracy'])} "
          f"({m_plataforma['acertos']}/{m_plataforma['total_arquivos']} arquivos)")
    for d in m_plataforma["detalhes"]:
        marca = "OK " if d["plataforma_correta"] else "ERRO"
        print(f"    [{marca}] {d['fonte']:<18} esperado={d['plataforma_esperada']:<10} "
              f"detectado={d['plataforma_detectada']}")

    # --- Classificação de ameaça ---
    print("\n[Classificação] Ameaça vs benigna/falso-positivo (Stage 1+2)")
    mc = m_classificacao["matriz_confusao"]
    print(f"  Total de amostras : {m_classificacao['total_amostras']}")
    print(f"  Accuracy          : {_fmt_pct(m_classificacao['accuracy'])}")
    print(f"  Precisão          : {_fmt_pct(m_classificacao['precisao'])}")
    print(f"  Recall            : {_fmt_pct(m_classificacao['recall'])}")
    print(f"  F1                : {_fmt_pct(m_classificacao['f1'])}")
    print(f"  Matriz de confusão: TP={mc['verdadeiro_positivo']} "
          f"FP={mc['falso_positivo']} FN={mc['falso_negativo']} TN={mc['verdadeiro_negativo']}")

    print("\n  Acerto de classificação por tipo de amostra:")
    for tipo, taxa in m_classificacao["taxa_acerto_classificacao_por_tipo"].items():
        print(f"    {tipo:<16} {_barra(taxa)} {taxa:.1%}")

    # --- Técnica MITRE ---
    print("\n[Técnica] Técnica MITRE correta (apenas amostras 'ameaca')")
    if m_tecnica.get("total_ameacas", 0) == 0:
        print("  Nenhuma amostra do tipo 'ameaca' no dataset.")
    else:
        print(f"  Total de ameaças esperadas    : {m_tecnica['total_ameacas']}")
        print(f"  Detectadas (qualquer técnica) : {m_tecnica['total_detectadas']} "
              f"({m_tecnica['taxa_deteccao']:.1%})")
        print(f"  Técnica correta (geral)       : {m_tecnica['total_tecnica_correta']} "
              f"({m_tecnica['taxa_tecnica_correta_geral']:.1%})")
        if m_tecnica["taxa_tecnica_correta_dado_detectado"] is not None:
            print(f"  Técnica correta | detectada   : "
                  f"{m_tecnica['taxa_tecnica_correta_dado_detectado']:.1%}")

        print("\n  Por tática (detecção / técnica correta):")
        for tatica, v in m_tecnica["taxa_por_tatica"].items():
            print(f"    {tatica:<22} {_barra(v['taxa_deteccao'])} {v['taxa_deteccao']:.1%}  "
                  f"| {_barra(v['taxa_tecnica_correta'])} {v['taxa_tecnica_correta']:.1%}")

        if m_tecnica["distribuicao_estagio_perda"]:
            print("\n  Ameaças não detectadas, por estágio de perda:")
            for estagio, n in m_tecnica["distribuicao_estagio_perda"].items():
                print(f"    {estagio:<28} {n}")

    print("\n" + "=" * 64)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Avalia o pipeline real de detecção de ameaças contra logs sintéticos."
    )
    parser.add_argument("--dataset", type=Path, default=DATASET_PADRAO,
                         help="Dataset de avaliação gerado por construtor_dataset.py")
    parser.add_argument("--saida", type=Path, default=SAIDA_PADRAO,
                         help="Onde salvar as métricas calculadas (JSON)")
    parser.add_argument("--pipeline-completo", action="store_true",
                         help="Executa o pipeline real (construtor_dataset) antes de avaliar")
    parser.add_argument("--dir-logs", type=Path, default=DIR_LOGS_SINTETICOS_PADRAO,
                         help="Diretório com logs sintéticos (usado com --pipeline-completo)")
    parser.add_argument("--batch-size", type=int, default=15)
    parser.add_argument("--top-k", type=int, default=3)
    parser.add_argument("--limiar-score", type=float, default=0.40)
    parser.add_argument("--analise-llm", action="store_true",
                         help="Gera também a análise textual do LLM por ameaça (mais lento)")
    args = parser.parse_args()

    if args.pipeline_completo:
        from construtor_dataset import ConstrutorDatasetAvaliacao

        construtor = ConstrutorDatasetAvaliacao(
            dir_logs=args.dir_logs,
            batch_size=args.batch_size,
            top_k=args.top_k,
            limiar_score=args.limiar_score,
            gerar_analise_llm=args.analise_llm,
        )
        dataset = construtor.construir()
        args.dataset.parent.mkdir(parents=True, exist_ok=True)
        args.dataset.write_text(json.dumps(dataset, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n[✓] Dataset de avaliação salvo: {args.dataset}")
    else:
        if not args.dataset.exists():
            print(f"[!] Dataset não encontrado: {args.dataset}")
            print("    Execute primeiro: python ragas/construtor_dataset.py")
            sys.exit(1)
        dataset = json.loads(args.dataset.read_text(encoding="utf-8"))

    amostras = dataset["amostras"]
    print(f"\n[*] Dataset carregado: {len(amostras)} amostras "
          f"de {len(dataset['resumo_plataformas'])} arquivo(s)")

    m_plataforma = calcular_metricas_plataforma(dataset["resumo_plataformas"])
    m_classificacao = calcular_metricas_classificacao_ameaca(amostras)
    m_tecnica = calcular_metricas_tecnica(amostras)

    imprimir_relatorio(m_plataforma, m_classificacao, m_tecnica)

    resultados = {
        "dataset_path": str(args.dataset),
        "total_amostras": len(amostras),
        "plataforma": m_plataforma,
        "classificacao_ameaca": m_classificacao,
        "tecnica": m_tecnica,
        "amostras": amostras,
    }
    args.saida.parent.mkdir(parents=True, exist_ok=True)
    args.saida.write_text(json.dumps(resultados, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[✓] Resultados salvos em: {args.saida}")


if __name__ == "__main__":
    main()
