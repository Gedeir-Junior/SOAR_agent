"""
pipeline_contextual/agente_comparador_contextual.py

Stage 3 do pipeline contextual — busca semântica pura por fase + síntese
narrativa do incidente.

Diferente do comparador linha-a-linha (AgenteComparadorAmeacas), este agente
chama SOMENTE RetrieverSemantico.buscar() (busca vetorial pura), nunca
buscar_hibrido/buscar_por_keywords — a query é a descricao_comportamental de
cada fase, não uma linha de log isolada.
"""
from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from services.groq_client import chamar_groq, extrair_json
from retriever.semantic_retriever import ResultadoBusca, RetrieverSemantico
from pipeline.agent_comparador_ameacas import _PLATAFORMA_MITRE_MAP
from pipeline.agente_filtrador_logs import LogFiltrado
from pipeline_contextual.agente_organizador_fases import FaseComportamental

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
CONTEXTUAL_TOP_K = int(os.getenv("CONTEXTUAL_TOP_K", "5"))
CONTEXTUAL_SCORE_THRESHOLD = float(os.getenv("CONTEXTUAL_SCORE_THRESHOLD", "0.45"))

_SYSTEM_PROMPT = (
    "Você é um analista de segurança sênior especializado em resposta a incidentes. "
    "Analise fases comportamentais de um ataque e técnicas MITRE ATT&CK e forneça "
    "análise técnica precisa. "
    "Responda SOMENTE com JSON válido, sem markdown nem explicações extras."
)


# ---------------------------------------------------------------------------
# Dataclasses de saída
# ---------------------------------------------------------------------------
@dataclass
class EvidenciaFase:
    numero_fase: int
    linha_inicio: int
    linha_fim: int
    descricao_comportamental: str
    score_similaridade: float


@dataclass
class AmeacaContextual:
    tecnica_id: str
    nome_tecnica: str
    tatica: str
    tatica_id: str
    severidade: str
    confianca_media: float
    descricao_mitre: str
    descricao_semantica_log: str
    plataformas_mitre: list[str]
    fases_relacionadas: list[EvidenciaFase]
    analise_llm: str = ""
    recomendacoes: list[str] = field(default_factory=list)
    url_mitre: str = ""

    @property
    def score_risco(self) -> float:
        """Score de risco composto — mesma fórmula/pesos de
        AmeacaDetectada.score_risco, usando len(fases_relacionadas) no lugar
        de len(evidencias)."""
        pesos = {"low": 0.25, "medium": 0.5, "high": 0.8, "critical": 1.0}
        peso = pesos.get(self.severidade.lower(), 0.5)
        media_scores = (
            sum(f.score_similaridade for f in self.fases_relacionadas) / len(self.fases_relacionadas)
            if self.fases_relacionadas else 0.0
        )
        penalidade = (
            0.7
            if len(self.fases_relacionadas) == 1 and self.severidade.lower() in {"high", "critical"}
            else 1.0
        )
        return round(media_scores * peso * self.confianca_media * penalidade, 4)

    @property
    def contagem_fases(self) -> int:
        return len(self.fases_relacionadas)


def _montar_trecho_bruto(fase: FaseComportamental, logs_por_linha: dict[int, str]) -> str:
    """Reconstrói o texto bruto (não resumido) das linhas da fase, na ordem
    original. Usado como query adicional na busca semântica: o resumo do LLM
    (`descricao_comportamental`) parafraseia o comportamento e descarta
    artefatos literais (domínios, extensões de arquivo, IPs, comandos) que o
    corpus MITRE também usa em seus exemplos — buscar com o texto bruto além
    do resumo recupera técnicas que o resumo sozinho não alcançava (ver achado
    de 15/08/2026: recall@10 de Initial Access foi de 0% para 25-50% nos 4
    cenários de teste usando o log bruto da fase como query)."""
    linhas = [
        logs_por_linha[n]
        for n in range(fase.linha_inicio, fase.linha_fim + 1)
        if n in logs_por_linha
    ]
    return "\n".join(linhas)


@dataclass
class RelatorioContextual:
    arquivo_log: str
    total_linhas_analisadas: int
    total_fases: int
    fases: list[FaseComportamental]
    ameacas: list[AmeacaContextual]
    narrativa_incidente: str = ""     # conta a sequência do ataque, ponta a ponta
    resumo_executivo: str = ""
    severidade_geral: str = "low"
    timestamp_geracao: str = ""

    def ameacas_por_severidade(self, severidade: str) -> list[AmeacaContextual]:
        return [a for a in self.ameacas if a.severidade.lower() == severidade.lower()]

    def taticas_unicas(self) -> list[str]:
        return sorted({a.tatica for a in self.ameacas})


# ---------------------------------------------------------------------------
# Geração de análise LLM por ameaça
# ---------------------------------------------------------------------------
def _gerar_analise_ameaca(ameaca: AmeacaContextual) -> tuple[str, list[str]]:
    """Pede ao LLM uma síntese técnica e recomendações para uma ameaça detectada."""
    fases_str = "\n".join(
        f"  Fase {f.numero_fase} (linhas {f.linha_inicio}-{f.linha_fim}, score={f.score_similaridade:.3f}): {f.descricao_comportamental}"
        for f in ameaca.fases_relacionadas[:5]  # máximo 5 fases no prompt
    )
    prompt = f"""Técnica MITRE detectada: {ameaca.tecnica_id} — {ameaca.nome_tecnica}
Tática: {ameaca.tatica} ({ameaca.tatica_id})
Severidade: {ameaca.severidade}
Descrição MITRE: {ameaca.descricao_mitre}
Como aparece em logs: {ameaca.descricao_semantica_log[:300]}

Fases relacionadas encontradas no arquivo de log:
{fases_str}

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
        raw = chamar_groq(prompt, _SYSTEM_PROMPT, temperature=0.2, origem="comparador_contextual")
        data = json.loads(extrair_json(raw))
        return data.get("analise", ""), data.get("recomendacoes", [])
    except Exception as exc:
        print(f"  [AVISO] Análise LLM falhou para {ameaca.tecnica_id}: {exc}", file=sys.stderr)
        return "", []


def _gerar_narrativa_incidente(relatorio: RelatorioContextual) -> tuple[str, str, str]:
    """Gera a narrativa do incidente ponta a ponta, resumo executivo e severidade geral."""
    fases_str = "\n".join(
        f"  Fase {f.numero_fase} (linhas {f.linha_inicio}-{f.linha_fim}, severidade={f.severidade_inferida}): "
        f"{f.titulo_fase} — {f.descricao_comportamental}"
        for f in relatorio.fases
    )

    tecnicas_por_fase: dict[int, list[str]] = defaultdict(list)
    for ameaca in relatorio.ameacas:
        for ev in ameaca.fases_relacionadas:
            tecnicas_por_fase[ev.numero_fase].append(f"{ameaca.tecnica_id} ({ameaca.nome_tecnica})")

    tecnicas_str = "\n".join(
        f"  Fase {num}: {', '.join(tecs)}"
        for num, tecs in sorted(tecnicas_por_fase.items())
    ) or "  Nenhuma técnica MITRE associada."

    prompt = f"""Analise a sequência de fases comportamentais abaixo, extraídas de um arquivo de log, e as técnicas MITRE ATT&CK associadas a cada fase:

Arquivo analisado: {relatorio.arquivo_log}
Total de linhas analisadas: {relatorio.total_linhas_analisadas}
Total de fases identificadas: {relatorio.total_fases}

Fases (em ordem cronológica):
{fases_str}

Técnicas MITRE por fase:
{tecnicas_str}

Retorne SOMENTE este JSON:
{{
  "narrativa_incidente": "<6-10 frases em português contando a sequência do incidente do início ao fim, na ordem cronológica das fases>",
  "resumo_executivo": "<4-6 frases em português para audiência executiva não-técnica: o que foi encontrado, qual o risco geral, qual a urgência de resposta>",
  "severidade_geral": "<low | medium | high | critical>"
}}"""

    try:
        raw = chamar_groq(prompt, _SYSTEM_PROMPT, temperature=0.2, origem="comparador_contextual")
        data = json.loads(extrair_json(raw))
        return (
            data.get("narrativa_incidente", ""),
            data.get("resumo_executivo", ""),
            data.get("severidade_geral", "medium"),
        )
    except Exception as exc:
        print(f"  [AVISO] Narrativa do incidente falhou: {exc}", file=sys.stderr)
        return "", "", "medium"


# ---------------------------------------------------------------------------
# Agente principal
# ---------------------------------------------------------------------------
class AgenteComparadorContextual:
    def __init__(
        self,
        top_k: int = CONTEXTUAL_TOP_K,
        limiar_score: float = CONTEXTUAL_SCORE_THRESHOLD,
        gerar_analise_llm: bool = True,
    ) -> None:
        self.top_k = top_k
        self.limiar_score = limiar_score
        self.gerar_analise_llm = gerar_analise_llm
        self._retriever = RetrieverSemantico(top_k=top_k, limiar_score=limiar_score)

    def analisar(
        self,
        fases: list[FaseComportamental],
        nome_arquivo_log: str = "desconhecido",
        plataforma_predominante: str = "desconhecida",
        total_linhas_analisadas: int = 0,
        logs_filtrados: list[LogFiltrado] | None = None,
    ) -> RelatorioContextual:
        """
        Ponto de entrada principal: recebe fases comportamentais ordenadas e
        retorna o relatório contextual completo.

        `logs_filtrados`: linhas originais (pré-resumo) do Stage 0, opcional.
        Quando fornecido, a busca semântica de cada fase é feita duas vezes —
        pelo resumo comportamental E pelo texto bruto das linhas da fase — e
        os candidatos são unidos (maior score por técnica). Sem isso, o
        comparador cai de volta ao comportamento anterior (busca só pelo
        resumo).
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        print(f"[*] Comparador contextual: {len(fases)} fase(s) para análise…")
        print(f"[*] Plataforma predominante: {plataforma_predominante}")

        plataformas_aceitas = _PLATAFORMA_MITRE_MAP.get(plataforma_predominante, set())

        logs_por_linha = (
            {lf.numero_linha: lf.linha_original for lf in logs_filtrados if not lf.foi_filtrado}
            if logs_filtrados
            else {}
        )

        # Agrupa fases relacionadas por tecnica_id
        mapa_ameacas: dict[str, dict] = defaultdict(lambda: {
            "resultado": None,
            "fases": [],
        })

        for fase in fases:
            resultados_por_id: dict[str, ResultadoBusca] = {}
            for resultado in self._retriever.buscar(
                query=fase.descricao_comportamental,
                top_k=self.top_k,
                limiar_score=self.limiar_score,
            ):
                resultados_por_id[resultado.tecnica_id] = resultado

            if logs_por_linha:
                trecho_bruto = _montar_trecho_bruto(fase, logs_por_linha)
                if trecho_bruto.strip():
                    for resultado in self._retriever.buscar(
                        query=trecho_bruto,
                        top_k=self.top_k,
                        limiar_score=self.limiar_score,
                    ):
                        existente = resultados_por_id.get(resultado.tecnica_id)
                        if existente is None or resultado.score > existente.score:
                            resultados_por_id[resultado.tecnica_id] = resultado

            resultados = sorted(resultados_por_id.values(), key=lambda r: r.score, reverse=True)

            for resultado in resultados:
                # Descarta técnicas incompatíveis com a plataforma predominante,
                # igual ao comparador linha-a-linha faz por linha.
                if plataformas_aceitas:
                    plataformas_tecnica = {p.lower() for p in resultado.plataformas_mitre}
                    if not plataformas_tecnica.intersection(plataformas_aceitas):
                        continue

                tid = resultado.tecnica_id
                if mapa_ameacas[tid]["resultado"] is None:
                    mapa_ameacas[tid]["resultado"] = resultado

                mapa_ameacas[tid]["fases"].append(
                    EvidenciaFase(
                        numero_fase=fase.numero_fase,
                        linha_inicio=fase.linha_inicio,
                        linha_fim=fase.linha_fim,
                        descricao_comportamental=fase.descricao_comportamental,
                        score_similaridade=resultado.score,
                    )
                )

        # Constrói AmeacaContextual e dedup por numero_fase
        ameacas: list[AmeacaContextual] = []
        for tid, dados in mapa_ameacas.items():
            resultado: ResultadoBusca = dados["resultado"]
            fases_raw: list[EvidenciaFase] = dados["fases"]

            fase_por_numero: dict[int, EvidenciaFase] = {}
            for ev in fases_raw:
                if ev.numero_fase not in fase_por_numero or ev.score_similaridade > fase_por_numero[ev.numero_fase].score_similaridade:
                    fase_por_numero[ev.numero_fase] = ev
            fases_unicas = sorted(fase_por_numero.values(), key=lambda e: e.numero_fase)

            confianca_media = round(
                sum(f.score_similaridade for f in fases_unicas) / len(fases_unicas), 4
            )

            ameaca = AmeacaContextual(
                tecnica_id=resultado.tecnica_id,
                nome_tecnica=resultado.nome_tecnica,
                tatica=resultado.tatica,
                tatica_id=resultado.tatica_id,
                severidade=resultado.severidade_sugerida,
                confianca_media=confianca_media,
                descricao_mitre=resultado.descricao_mitre,
                descricao_semantica_log=resultado.descricao_semantica_log,
                plataformas_mitre=resultado.plataformas_mitre,
                fases_relacionadas=fases_unicas,
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
        relatorio = RelatorioContextual(
            arquivo_log=nome_arquivo_log,
            total_linhas_analisadas=total_linhas_analisadas,
            total_fases=len(fases),
            fases=fases,
            ameacas=ameacas,
            timestamp_geracao=timestamp,
        )

        # Gera narrativa do incidente + resumo executivo
        if fases:
            print("[*] Gerando narrativa do incidente…")
            narrativa, resumo, severidade_geral = _gerar_narrativa_incidente(relatorio)
            relatorio.narrativa_incidente = narrativa
            relatorio.resumo_executivo = resumo
            relatorio.severidade_geral = severidade_geral

        print(f"[+] Comparador contextual concluído: {len(ameacas)} ameaça(s) detectada(s).")
        return relatorio


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    import dataclasses

    from pipeline_contextual.agente_organizador_fases import FaseComportamental as _Fase

    parser = argparse.ArgumentParser(description="Compara fases comportamentais com banco vetorial MITRE (busca semântica pura).")
    parser.add_argument("fases_json", type=Path, help="JSON de saída do agente organizador de fases.")
    parser.add_argument("--saida", type=Path, default=None)
    parser.add_argument("--top-k", type=int, default=CONTEXTUAL_TOP_K)
    parser.add_argument("--threshold", type=float, default=CONTEXTUAL_SCORE_THRESHOLD)
    parser.add_argument("--sem-llm", action="store_true", help="Pula análise LLM por ameaça.")
    args = parser.parse_args()

    dados = json.loads(args.fases_json.read_text(encoding="utf-8"))
    fases = [_Fase(**d) for d in dados]

    agente = AgenteComparadorContextual(
        top_k=args.top_k,
        limiar_score=args.threshold,
        gerar_analise_llm=not args.sem_llm,
    )
    relatorio = agente.analisar(
        fases,
        nome_arquivo_log=args.fases_json.stem,
        total_linhas_analisadas=sum(f.linha_fim - f.linha_inicio + 1 for f in fases),
    )

    if args.saida:
        args.saida.write_text(
            json.dumps(dataclasses.asdict(relatorio), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"[+] Relatório salvo em: {args.saida}")
    else:
        for ameaca in relatorio.ameacas:
            print(f"\n[{ameaca.severidade.upper()}] {ameaca.tecnica_id} — {ameaca.nome_tecnica}")
            print(f"  Fases relacionadas: {ameaca.contagem_fases} | Score risco: {ameaca.score_risco}")
