"""
ragas/construtor_dataset.py

Constrói o dataset de avaliação cruzando o gabarito dos logs sintéticos
(*-metadata.json, gerado por gerador_logs_siteticos.py) com a saída do
PIPELINE REAL (pipeline_runner.executar_pipeline_real), que roda
AgenteFiltadorLogs -> AgenteTradutorLogs -> AgenteComparadorAmeacas.

Diferente da versão anterior, nenhuma lógica de detecção é reimplementada
aqui: o pipeline avaliado é o mesmo usado em produção (main.py). Isso remove
o viés de avaliar um "pipeline simulado" que tinha acesso direto às mesmas
palavras-chave/índice MITRE usados para gerar o gabarito.

Para cada linha de log, o dataset registra:
  - plataforma esperada (derivada da fonte) vs plataforma detectada (Stage 0)
  - tipo esperado (ameaca | benigna | falso_positivo) vs se o pipeline
    classificou a linha como evidência de alguma ameaça (Stage 2)
  - técnica MITRE esperada vs técnica(s) detectada(s) para a linha
  - em qual estágio a ameaça se perdeu, quando não detectada
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from pipeline_runner import ResultadoPipeline, executar_pipeline_real

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
DIR_LOGS_SINTETICOS = Path("./ragas/resultados")
SAIDA_PADRAO = Path("./ragas/resultados/dataset_avaliacao.json")

# Mapeia a "fonte" do gerador de logs sintéticos para a "plataforma" usada
# pelo AgenteFiltadorLogs (Stage 0).
FONTE_PARA_PLATAFORMA = {
    "linux_syslog": "linux",
    "windows_eventlog": "windows",
    "macos_unified_log": "macos",
    "rede": "network",
}

SEVERIDADES_RELEVANTES = {"low", "medium", "high", "critical"}


# ---------------------------------------------------------------------------
# Construtor
# ---------------------------------------------------------------------------
class ConstrutorDatasetAvaliacao:
    """
    Para cada par (<fonte>.log, <fonte>-metadata.json) em `dir_logs`, executa
    o pipeline real e cruza o resultado com o gabarito.
    """

    def __init__(
        self,
        dir_logs: Path,
        batch_size: int = 15,
        top_k: int = 3,
        limiar_score: float = 0.40,
        gerar_analise_llm: bool = False,
    ):
        self.dir_logs = dir_logs
        self.pipeline_kwargs = dict(
            batch_size=batch_size,
            top_k=top_k,
            limiar_score=limiar_score,
            gerar_analise_llm=gerar_analise_llm,
        )

    def construir(self) -> dict:
        amostras: list[dict] = []
        resumo_plataformas: list[dict] = []

        metadados = sorted(self.dir_logs.glob("*-metadata.json"))
        if not metadados:
            raise FileNotFoundError(
                f"Nenhum *-metadata.json encontrado em {self.dir_logs}. "
                f"Execute primeiro gerador_logs_siteticos.py."
            )

        for path_meta in metadados:
            nome_base = path_meta.name[: -len("-metadata.json")]
            path_log = self.dir_logs / f"{nome_base}.log"
            if not path_log.exists():
                print(f"[!] Log não encontrado para {path_meta.name}, ignorando.")
                continue

            gabarito = json.loads(path_meta.read_text(encoding="utf-8"))
            if not gabarito:
                continue
            fonte = gabarito[0]["fonte"]
            plataforma_esperada = FONTE_PARA_PLATAFORMA.get(fonte, "desconhecida")

            print(f"\n[*] Executando pipeline real para: {path_log.name} (fonte={fonte})")
            resultado = executar_pipeline_real(path_log, **self.pipeline_kwargs)
            print(
                f"    Plataforma esperada={plataforma_esperada} | "
                f"detectada={resultado.plataforma_detectada}"
            )

            resumo_plataformas.append({
                "fonte": fonte,
                "arquivo": path_log.name,
                "plataforma_esperada": plataforma_esperada,
                "plataforma_detectada": resultado.plataforma_detectada,
                "plataforma_correta": resultado.plataforma_detectada == plataforma_esperada,
            })

            amostras.extend(
                self._cruzar_gabarito(gabarito, resultado, fonte, plataforma_esperada)
            )

        return {"resumo_plataformas": resumo_plataformas, "amostras": amostras}

    # ------------------------------------------------------------------
    # Cruza o gabarito de um arquivo com a saída do pipeline real
    # ------------------------------------------------------------------
    @staticmethod
    def _cruzar_gabarito(
        gabarito: list[dict],
        resultado: ResultadoPipeline,
        fonte: str,
        plataforma_esperada: str,
    ) -> list[dict]:
        # Stage 0: quais linhas foram descartadas como inofensivas
        filtrado_por_linha = {
            lf.numero_linha: lf.foi_filtrado for lf in resultado.logs_filtrados
        }

        # Stage 1: severidade inferida pelo tradutor (linhas filtradas não aparecem aqui)
        severidade_por_linha = {
            t.numero_linha: t.severidade_inferida for t in resultado.traducoes
        }

        # Stage 2: técnica(s) atribuídas a cada linha, por ela ter sido usada
        # como evidência de uma AmeacaDetectada
        deteccoes_por_linha: dict[int, list[dict]] = {}
        for ameaca in resultado.relatorio.ameacas:
            for ev in ameaca.evidencias:
                deteccoes_por_linha.setdefault(ev.numero_linha, []).append({
                    "tecnica_id": ameaca.tecnica_id,
                    "nome_tecnica": ameaca.nome_tecnica,
                    "tatica": ameaca.tatica,
                    "severidade": ameaca.severidade,
                    "score": ev.score_similaridade,
                })

        amostras = []
        for entrada in gabarito:
            num = entrada["linha_numero"]
            tipo_esperado = entrada.get("tipo", "benigna")
            tecnica_esperada = entrada.get("tecnica_id", "")
            if tecnica_esperada in {"BENIGNO", "FALSO_POSITIVO"}:
                tecnica_esperada = ""

            deteccoes = sorted(
                deteccoes_por_linha.get(num, []),
                key=lambda d: d["score"],
                reverse=True,
            )
            principal = deteccoes[0] if deteccoes else None

            foi_filtrado = filtrado_por_linha.get(num)
            severidade_estagio1 = severidade_por_linha.get(num)

            # Diagnóstico: em qual estágio uma ameaça esperada deixou de ser detectada
            if deteccoes:
                estagio_perda = None
            elif foi_filtrado:
                estagio_perda = "filtrado_estagio0"
            elif severidade_estagio1 not in SEVERIDADES_RELEVANTES:
                estagio_perda = "severidade_baixa_estagio1"
            else:
                estagio_perda = "nao_encontrado_estagio2"

            amostras.append({
                "linha_numero": num,
                "fonte": fonte,
                "linha_texto": entrada["linha_texto"],
                "plataforma_esperada": plataforma_esperada,

                "tipo_esperado": tipo_esperado,
                "e_ameaca_esperada": tipo_esperado == "ameaca",
                "tecnica_esperada": tecnica_esperada,
                "nome_tecnica_esperada": entrada.get("nome_tecnica", ""),
                "tatica_esperada": entrada.get("tatica", ""),
                "severidade_esperada": entrada.get("severidade", "info"),

                "foi_filtrado_estagio0": foi_filtrado,
                "severidade_detectada_estagio1": severidade_estagio1,
                "e_ameaca_detectada": bool(deteccoes),
                "tecnicas_detectadas": [d["tecnica_id"] for d in deteccoes],
                "tecnica_detectada": principal["tecnica_id"] if principal else None,
                "nome_tecnica_detectada": principal["nome_tecnica"] if principal else None,
                "tatica_detectada": principal["tatica"] if principal else None,
                "severidade_detectada": principal["severidade"] if principal else None,
                "score_similaridade": principal["score"] if principal else None,
                "estagio_perda": estagio_perda,
            })

        return amostras


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Constrói o dataset de avaliação executando o pipeline real "
        "sobre os logs sintéticos e cruzando com o gabarito."
    )
    parser.add_argument("--dir-logs", type=Path, default=DIR_LOGS_SINTETICOS,
                         help="Diretório com *.log e *-metadata.json sintéticos.")
    parser.add_argument("--saida", type=Path, default=SAIDA_PADRAO,
                         help="Caminho do dataset de avaliação (JSON) a ser salvo.")
    parser.add_argument("--batch-size", type=int, default=15,
                         help="Linhas por lote enviado ao tradutor (Stage 1).")
    parser.add_argument("--top-k", type=int, default=3,
                         help="Top-K resultados na busca semântica (Stage 2).")
    parser.add_argument("--limiar-score", type=float, default=0.40,
                         help="Score mínimo de similaridade no comparador (Stage 2).")
    parser.add_argument("--analise-llm", action="store_true",
                         help="Gera também a análise textual do LLM por ameaça (mais lento).")
    args = parser.parse_args()

    construtor = ConstrutorDatasetAvaliacao(
        dir_logs=args.dir_logs,
        batch_size=args.batch_size,
        top_k=args.top_k,
        limiar_score=args.limiar_score,
        gerar_analise_llm=args.analise_llm,
    )
    dataset = construtor.construir()

    args.saida.parent.mkdir(parents=True, exist_ok=True)
    args.saida.write_text(json.dumps(dataset, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n[✓] Dataset de avaliação salvo: {args.saida} ({len(dataset['amostras'])} amostras)")


if __name__ == "__main__":
    main()
