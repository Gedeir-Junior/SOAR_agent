"""
ragas_contextual/construtor_dataset_contextual.py

Constrói o dataset de avaliação RAGAS do pipeline contextual, cruzando o
gabarito dos cenários multi-fase (*-gabarito.json, gerado por
gerador_logs_multifase.py) com a saída do PIPELINE REAL
(pipeline_runner_contextual.executar_pipeline_contextual_real).

Três blocos de amostras são produzidos, cada um alimentando uma métrica
diferente em avaliador_contextual.py:

  1. amostras_contexto        -> Context Precision / Context Recall
     Por fase do gabarito, casada por sobreposição de linhas com a(s) fase(s)
     detectada(s) pelo AgenteOrganizadorFases; contexto = candidatos brutos do
     RetrieverSemantico para aquela(s) fase(s).

  2. amostras_geracao_documento -> Faithfulness / Answer Relevancy da síntese
     narrativa_incidente/resumo_executivo (RelatorioContextual inteiro).

  3. amostras_geracao_ameaca    -> Faithfulness / Answer Relevancy da
     analise_llm por AmeacaContextual (síntese técnica por técnica MITRE).

Também registra checks_estruturais por arquivo (fases fora de ordem ou
sobrepostas, total de fases esperado vs. detectado) — sinal barato e
determinístico que não depende de juiz LLM.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from pipeline_contextual.agente_organizador_fases import FaseComportamental
from ragas_contextual.pipeline_runner_contextual import (
    ResultadoPipelineContextual,
    executar_pipeline_contextual_real,
)

DIR_CENARIOS_PADRAO = Path("./ragas_contextual/resultados")
SAIDA_PADRAO = Path("./ragas_contextual/resultados/dataset_contextual.json")


# ---------------------------------------------------------------------------
# Checks estruturais (determinísticos, sem juiz LLM)
# ---------------------------------------------------------------------------
def _checar_fases_sem_sobreposicao(fases: list[FaseComportamental]) -> tuple[bool, list[str]]:
    problemas: list[str] = []
    ordenadas = sorted(fases, key=lambda f: f.numero_fase)
    for i in range(len(ordenadas) - 1):
        atual, prox = ordenadas[i], ordenadas[i + 1]
        if prox.linha_inicio < atual.linha_inicio:
            problemas.append(
                f"Fase {prox.numero_fase} (L{prox.linha_inicio}) começa antes da "
                f"fase {atual.numero_fase} (L{atual.linha_inicio}) — fora de ordem."
            )
        elif atual.linha_fim >= prox.linha_inicio:
            problemas.append(
                f"Fase {atual.numero_fase} (L{atual.linha_inicio}-{atual.linha_fim}) se "
                f"sobrepõe à fase {prox.numero_fase} (L{prox.linha_inicio}-{prox.linha_fim})."
            )
    return (len(problemas) == 0, problemas)


# ---------------------------------------------------------------------------
# Casamento de fase do gabarito -> fase(s) detectada(s) por sobreposição de linhas
# ---------------------------------------------------------------------------
def _sobrepoe(a_inicio: int, a_fim: int, b_inicio: int, b_fim: int) -> bool:
    return max(a_inicio, b_inicio) <= min(a_fim, b_fim)


def _casar_fase_gabarito(fase_gabarito: dict, fases_detectadas: list[FaseComportamental]) -> list[FaseComportamental]:
    return [
        f for f in fases_detectadas
        if _sobrepoe(fase_gabarito["linha_inicio"], fase_gabarito["linha_fim"], f.linha_inicio, f.linha_fim)
    ]


# ---------------------------------------------------------------------------
# Construtor
# ---------------------------------------------------------------------------
class ConstrutorDatasetContextual:
    def __init__(
        self,
        dir_cenarios: Path,
        chunk_size: int = 80,
        reduce_batch_size: int = 20,
        top_k: int = 5,
        limiar_score: float = 0.45,
        gerar_analise_llm: bool = True,
    ):
        self.dir_cenarios = dir_cenarios
        self.pipeline_kwargs = dict(
            chunk_size=chunk_size,
            reduce_batch_size=reduce_batch_size,
            top_k=top_k,
            limiar_score=limiar_score,
            gerar_analise_llm=gerar_analise_llm,
        )

    def construir(self) -> dict:
        amostras_contexto: list[dict] = []
        amostras_geracao_documento: list[dict] = []
        amostras_geracao_ameaca: list[dict] = []
        checks_estruturais: list[dict] = []
        resumo_plataformas: list[dict] = []

        gabaritos = sorted(self.dir_cenarios.glob("*-gabarito.json"))
        if not gabaritos:
            raise FileNotFoundError(
                f"Nenhum *-gabarito.json encontrado em {self.dir_cenarios}. "
                f"Execute primeiro gerador_logs_multifase.py."
            )

        for path_gabarito in gabaritos:
            cenario = json.loads(path_gabarito.read_text(encoding="utf-8"))
            path_log = self.dir_cenarios / cenario["arquivo_log"]
            if not path_log.exists():
                print(f"[!] Log não encontrado para {path_gabarito.name}, ignorando.")
                continue

            print(f"\n[*] Executando pipeline contextual real para: {path_log.name}")
            resultado = executar_pipeline_contextual_real(path_log, **self.pipeline_kwargs)

            resumo_plataformas.append({
                "arquivo": path_log.name,
                "fonte": cenario["fonte"],
                "plataforma_esperada": self._plataforma_esperada(cenario["fonte"]),
                "plataforma_detectada": resultado.plataforma_detectada,
            })

            amostras_contexto.extend(self._montar_amostras_contexto(cenario, resultado))
            amostras_geracao_documento.append(self._montar_amostra_documento(cenario, resultado))
            amostras_geracao_ameaca.extend(self._montar_amostras_ameaca(cenario, resultado))
            checks_estruturais.append(self._montar_check_estrutural(cenario, resultado))

        return {
            "resumo_plataformas": resumo_plataformas,
            "amostras_contexto": amostras_contexto,
            "amostras_geracao_documento": amostras_geracao_documento,
            "amostras_geracao_ameaca": amostras_geracao_ameaca,
            "checks_estruturais": checks_estruturais,
        }

    @staticmethod
    def _plataforma_esperada(fonte: str) -> str:
        return {
            "linux_syslog": "linux",
            "windows_eventlog": "windows",
            "macos_unified_log": "macos",
            "rede": "network",
        }.get(fonte, "desconhecida")

    # ------------------------------------------------------------------
    # 1) Amostras de contexto (Context Precision / Recall)
    # ------------------------------------------------------------------
    @staticmethod
    def _montar_amostras_contexto(cenario: dict, resultado: ResultadoPipelineContextual) -> list[dict]:
        amostras = []
        for fase_g in cenario["fases"]:
            detectadas = _casar_fase_gabarito(fase_g, resultado.fases)

            tecnicas_recuperadas: dict[str, dict] = {}
            for f in detectadas:
                for c in resultado.candidatos_por_fase.get(f.numero_fase, []):
                    atual = tecnicas_recuperadas.get(c.tecnica_id)
                    if atual is None or c.score > atual["score"]:
                        tecnicas_recuperadas[c.tecnica_id] = {
                            "tecnica_id": c.tecnica_id,
                            "nome_tecnica": c.nome_tecnica,
                            "score": c.score,
                            "descricao_mitre": c.descricao_mitre,
                        }

            amostras.append({
                "arquivo": cenario["arquivo_log"],
                "fonte": cenario["fonte"],
                "numero_fase_esperado": fase_g["numero_fase_esperado"],
                "tatica_esperada": fase_g["tatica_esperada"],
                "linha_inicio_esperado": fase_g["linha_inicio"],
                "linha_fim_esperado": fase_g["linha_fim"],
                "tecnicas_esperadas": fase_g["tecnicas_esperadas"],
                "fases_detectadas_sobrepostas": [f.numero_fase for f in detectadas],
                "query": " ".join(f.descricao_comportamental for f in detectadas),
                "tecnicas_recuperadas": sorted(
                    tecnicas_recuperadas.values(), key=lambda t: t["score"], reverse=True
                ),
            })
        return amostras

    # ------------------------------------------------------------------
    # 2) Amostra de geração em nível de documento (narrativa + resumo)
    # ------------------------------------------------------------------
    @staticmethod
    def _montar_amostra_documento(cenario: dict, resultado: ResultadoPipelineContextual) -> dict:
        relatorio = resultado.relatorio
        contexto_fases = "\n".join(
            f"Fase {f.numero_fase} ({f.titulo_fase}): {f.descricao_comportamental}"
            for f in resultado.fases
        )
        contexto_tecnicas = "\n".join(
            f"{a.tecnica_id} ({a.nome_tecnica}) — tática {a.tatica}: {a.descricao_mitre[:300]}"
            for a in relatorio.ameacas
        )
        return {
            "arquivo": cenario["arquivo_log"],
            "pergunta": (
                "Conte a sequência cronológica deste incidente, do início ao fim, "
                "e avalie o risco geral e a urgência de resposta."
            ),
            "contexto": f"{contexto_fases}\n\nTécnicas MITRE identificadas:\n{contexto_tecnicas}",
            "resposta_narrativa": relatorio.narrativa_incidente,
            "resposta_resumo": relatorio.resumo_executivo,
            "titulos_fases_em_ordem": [f.titulo_fase for f in sorted(resultado.fases, key=lambda f: f.numero_fase)],
        }

    # ------------------------------------------------------------------
    # 3) Amostras de geração por ameaça (analise_llm)
    # ------------------------------------------------------------------
    @staticmethod
    def _montar_amostras_ameaca(cenario: dict, resultado: ResultadoPipelineContextual) -> list[dict]:
        amostras = []
        for ameaca in resultado.relatorio.ameacas:
            if not ameaca.analise_llm.strip():
                continue
            contexto_fases = "\n".join(
                f"Fase {ev.numero_fase} (L{ev.linha_inicio}-{ev.linha_fim}): {ev.descricao_comportamental}"
                for ev in ameaca.fases_relacionadas
            )
            amostras.append({
                "arquivo": cenario["arquivo_log"],
                "tecnica_id": ameaca.tecnica_id,
                "nome_tecnica": ameaca.nome_tecnica,
                "pergunta": (
                    f"O que a técnica {ameaca.tecnica_id} ({ameaca.nome_tecnica}) revela "
                    f"sobre este incidente, qual o risco imediato e quais sistemas estão expostos?"
                ),
                "contexto": f"Descrição MITRE: {ameaca.descricao_mitre}\n\nFases relacionadas:\n{contexto_fases}",
                "resposta": ameaca.analise_llm,
            })
        return amostras

    # ------------------------------------------------------------------
    # 4) Checks estruturais
    # ------------------------------------------------------------------
    @staticmethod
    def _montar_check_estrutural(cenario: dict, resultado: ResultadoPipelineContextual) -> dict:
        sem_sobreposicao, problemas = _checar_fases_sem_sobreposicao(resultado.fases)
        return {
            "arquivo": cenario["arquivo_log"],
            "total_fases_esperado": len(cenario["fases"]),
            "total_fases_detectado": len(resultado.fases),
            "fases_ordenadas_sem_sobreposicao": sem_sobreposicao,
            "problemas_ordem": problemas,
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Constrói o dataset de avaliação RAGAS executando o pipeline "
        "contextual real sobre os cenários multi-fase e cruzando com o gabarito."
    )
    parser.add_argument("--dir-cenarios", type=Path, default=DIR_CENARIOS_PADRAO)
    parser.add_argument("--saida", type=Path, default=SAIDA_PADRAO)
    parser.add_argument("--chunk-size", type=int, default=80)
    parser.add_argument("--reduce-batch-size", type=int, default=20)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--limiar-score", type=float, default=0.45)
    parser.add_argument(
        "--sem-analise-llm", action="store_true",
        help="Pula a análise LLM por ameaça (narrativa/resumo do documento ainda são geradas).",
    )
    args = parser.parse_args()

    construtor = ConstrutorDatasetContextual(
        dir_cenarios=args.dir_cenarios,
        chunk_size=args.chunk_size,
        reduce_batch_size=args.reduce_batch_size,
        top_k=args.top_k,
        limiar_score=args.limiar_score,
        gerar_analise_llm=not args.sem_analise_llm,
    )
    dataset = construtor.construir()

    args.saida.parent.mkdir(parents=True, exist_ok=True)
    args.saida.write_text(json.dumps(dataset, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        f"\n[✓] Dataset de avaliação contextual salvo: {args.saida} "
        f"({len(dataset['amostras_contexto'])} amostras de contexto, "
        f"{len(dataset['amostras_geracao_documento'])} documento(s), "
        f"{len(dataset['amostras_geracao_ameaca'])} amostra(s) de ameaça)"
    )


if __name__ == "__main__":
    main()
