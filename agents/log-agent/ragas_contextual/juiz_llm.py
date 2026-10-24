"""
ragas_contextual/juiz_llm.py

Juiz LLM (via Groq) para as métricas RAGAS que exigem avaliar texto gerado, não
só recuperação: Faithfulness e Answer Relevancy. Inclui também um terceiro
julgamento (ordem cronológica da narrativa) que não é uma métrica RAGAS
clássica, mas usa o mesmo padrão de juiz e é específico deste pipeline.

Reaproveita services/groq_client.py (chamar_groq/extrair_json) — mesmo helper
usado pelos agentes do pipeline_contextual — e o modelo de embeddings local
(sentence-transformers, já usado pelo RetrieverSemantico) para a parte de
similaridade do Answer Relevancy. Isso evita depender de embeddings da OpenAI,
que é o padrão da lib `ragas` oficial.

Faithfulness (RAGAS): decompõe a resposta em afirmações atômicas, depois julga
cada uma como sustentada ou não pelo contexto fornecido. Score = fração de
afirmações sustentadas.

Answer Relevancy (RAGAS): gera N perguntas "reversas" a partir da resposta,
mede a similaridade de cosseno média entre essas perguntas e a pergunta
original. Score alto = a resposta responde de fato à pergunta. Score baixo =
resposta genérica ou fora do assunto.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from services.groq_client import chamar_groq, extrair_json

_SYSTEM_PROMPT_JUIZ = (
    "Você é um juiz técnico rigoroso de qualidade de respostas geradas por IA "
    "em relatórios de segurança da informação. Seja crítico e objetivo — não "
    "dê benefício da dúvida a afirmações vagas ou não sustentadas pelo "
    "contexto fornecido. Responda SOMENTE com JSON válido, sem markdown nem "
    "explicações extras."
)

N_PERGUNTAS_RELEVANCIA = int(os.getenv("RAGAS_N_PERGUNTAS_RELEVANCIA", "3"))


# ---------------------------------------------------------------------------
# Encoder de embeddings (lazy singleton) — mesmo modelo do RetrieverSemantico,
# carregado independente do cliente Qdrant (o juiz não consulta o banco).
# ---------------------------------------------------------------------------
_ENCODER = None


def _obter_encoder():
    global _ENCODER
    if _ENCODER is None:
        from sentence_transformers import SentenceTransformer
        modelo = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
        print(f"[*] Juiz: carregando modelo de embeddings '{modelo}'…")
        _ENCODER = SentenceTransformer(modelo)
    return _ENCODER


def _similaridade_cosseno(a, b) -> float:
    import numpy as np
    a = np.asarray(a)
    b = np.asarray(b)
    denom = float(np.linalg.norm(a) * np.linalg.norm(b))
    if denom == 0:
        return 0.0
    return float(np.dot(a, b) / denom)


# ---------------------------------------------------------------------------
# Faithfulness
# ---------------------------------------------------------------------------
@dataclass
class AvaliacaoFaithfulness:
    score: Optional[float]
    total_afirmacoes: int
    afirmacoes_sustentadas: int
    afirmacoes: list[dict] = field(default_factory=list)
    erro: str = ""


def _decompor_em_afirmacoes(resposta: str) -> list[str]:
    prompt = f"""Decomponha o texto abaixo em afirmações atômicas — frases curtas e independentes,
cada uma contendo exatamente UM fato verificável. Não inclua opiniões genéricas
nem recomendações de ação, apenas afirmações factuais sobre o que aconteceu.

Texto:
\"\"\"{resposta}\"\"\"

Retorne SOMENTE este JSON:
{{"afirmacoes": ["<afirmação atômica 1>", "<afirmação atômica 2>", "..."]}}"""
    raw = chamar_groq(prompt, _SYSTEM_PROMPT_JUIZ, temperature=0.0, origem="juiz_faithfulness_decompor")
    data = json.loads(extrair_json(raw))
    return [a for a in data.get("afirmacoes", []) if a and a.strip()]


def _julgar_afirmacoes(afirmacoes: list[str], contexto: str) -> list[dict]:
    bloco = "\n".join(f"{i+1}. {a}" for i, a in enumerate(afirmacoes))
    prompt = f"""Contexto disponível (única fonte de verdade permitida):
\"\"\"{contexto}\"\"\"

Afirmações a julgar:
{bloco}

Para cada afirmação, diga se ela é DIRETAMENTE sustentada pelo contexto acima.
Uma afirmação só é sustentada se o contexto contém informação suficiente para
confirmá-la — inferências razoáveis contam, mas invenções e generalizações não
sustentadas pelo texto do contexto NÃO contam.

Retorne SOMENTE este JSON:
{{"julgamentos": [
  {{"indice": 1, "sustentada": true, "justificativa": "<1 frase>"}}
]}}"""
    raw = chamar_groq(prompt, _SYSTEM_PROMPT_JUIZ, temperature=0.0, origem="juiz_faithfulness_julgar")
    data = json.loads(extrair_json(raw))
    julgamentos = {j.get("indice"): j for j in data.get("julgamentos", [])}

    resultado = []
    for i, afirmacao in enumerate(afirmacoes, 1):
        j = julgamentos.get(i, {})
        resultado.append({
            "afirmacao": afirmacao,
            "sustentada": bool(j.get("sustentada", False)),
            "justificativa": j.get("justificativa", ""),
        })
    return resultado


def avaliar_faithfulness(resposta: str, contexto: str) -> AvaliacaoFaithfulness:
    """Mede o quanto `resposta` (texto gerado pelo LLM do pipeline) é fiel a
    `contexto` (o que foi de fato recuperado/observado) — sem alucinação."""
    if not resposta.strip() or not contexto.strip():
        return AvaliacaoFaithfulness(
            score=None, total_afirmacoes=0, afirmacoes_sustentadas=0,
            erro="resposta ou contexto vazio",
        )

    try:
        afirmacoes = _decompor_em_afirmacoes(resposta)
        if not afirmacoes:
            return AvaliacaoFaithfulness(
                score=None, total_afirmacoes=0, afirmacoes_sustentadas=0,
                erro="nenhuma afirmação extraída",
            )

        julgadas = _julgar_afirmacoes(afirmacoes, contexto)
        sustentadas = sum(1 for j in julgadas if j["sustentada"])
        score = round(sustentadas / len(julgadas), 4)
        return AvaliacaoFaithfulness(
            score=score,
            total_afirmacoes=len(julgadas),
            afirmacoes_sustentadas=sustentadas,
            afirmacoes=julgadas,
        )
    except Exception as exc:
        print(f"  [AVISO juiz faithfulness] {exc}", file=sys.stderr)
        return AvaliacaoFaithfulness(
            score=None, total_afirmacoes=0, afirmacoes_sustentadas=0, erro=str(exc),
        )


# ---------------------------------------------------------------------------
# Answer Relevancy
# ---------------------------------------------------------------------------
@dataclass
class AvaliacaoRelevancia:
    score: Optional[float]
    perguntas_geradas: list[str] = field(default_factory=list)
    similaridades: list[float] = field(default_factory=list)
    erro: str = ""


def _gerar_perguntas_reversas(resposta: str, n: int) -> list[str]:
    prompt = f"""Leia a resposta abaixo, gerada por um analista de segurança sobre um incidente.
Gere {n} perguntas DIFERENTES que essa resposta responderia diretamente — ou
seja, faça a "engenharia reversa" da pergunta a partir da resposta.

Resposta:
\"\"\"{resposta}\"\"\"

Retorne SOMENTE este JSON:
{{"perguntas": ["<pergunta 1>", "<pergunta 2>"]}}"""
    raw = chamar_groq(prompt, _SYSTEM_PROMPT_JUIZ, temperature=0.3, origem="juiz_relevancy_perguntas")
    data = json.loads(extrair_json(raw))
    return [p for p in data.get("perguntas", []) if p and p.strip()][:n]


def avaliar_answer_relevancy(
    pergunta: str,
    resposta: str,
    n_perguntas: int = N_PERGUNTAS_RELEVANCIA,
) -> AvaliacaoRelevancia:
    """Mede o quanto `resposta` responde de fato a `pergunta` (a query
    original — aqui, a descrição comportamental da(s) fase(s) ou o objetivo da
    síntese do incidente)."""
    if not resposta.strip() or not pergunta.strip():
        return AvaliacaoRelevancia(score=None, erro="pergunta ou resposta vazia")

    try:
        perguntas_geradas = _gerar_perguntas_reversas(resposta, n_perguntas)
        if not perguntas_geradas:
            return AvaliacaoRelevancia(score=None, erro="nenhuma pergunta reversa gerada")

        encoder = _obter_encoder()
        vetor_original = encoder.encode(pergunta)
        vetores_geradas = encoder.encode(perguntas_geradas)

        similaridades = [
            round(_similaridade_cosseno(vetor_original, v), 4)
            for v in vetores_geradas
        ]
        score = round(sum(similaridades) / len(similaridades), 4)
        return AvaliacaoRelevancia(
            score=score,
            perguntas_geradas=perguntas_geradas,
            similaridades=similaridades,
        )
    except Exception as exc:
        print(f"  [AVISO juiz relevancy] {exc}", file=sys.stderr)
        return AvaliacaoRelevancia(score=None, erro=str(exc))


# ---------------------------------------------------------------------------
# Ordem cronológica da narrativa — check estrutural específico deste pipeline,
# não uma métrica RAGAS clássica, mas reaproveita o mesmo juiz.
# ---------------------------------------------------------------------------
@dataclass
class AvaliacaoOrdemNarrativa:
    ordem_correta: Optional[bool]
    justificativa: str = ""
    erro: str = ""


def avaliar_ordem_narrativa(narrativa: str, fases_em_ordem: list[str]) -> AvaliacaoOrdemNarrativa:
    """Verifica se `narrativa` (RelatorioContextual.narrativa_incidente) conta
    os eventos na mesma ordem cronológica de `fases_em_ordem` (títulos de fase
    já ordenados por numero_fase)."""
    if not narrativa.strip() or not fases_em_ordem:
        return AvaliacaoOrdemNarrativa(ordem_correta=None, erro="narrativa ou fases vazias")

    fases_str = "\n".join(f"{i+1}. {t}" for i, t in enumerate(fases_em_ordem))
    prompt = f"""Fases do incidente, na ordem cronológica REAL em que ocorreram:
{fases_str}

Narrativa gerada:
\"\"\"{narrativa}\"\"\"

A narrativa conta os eventos na MESMA ordem cronológica listada acima (sem
inverter a sequência das fases)? Pequenas omissões de fase são aceitáveis,
desde que a ordem relativa das fases mencionadas esteja correta.

Retorne SOMENTE este JSON:
{{"ordem_correta": true, "justificativa": "<1-2 frases>"}}"""
    try:
        raw = chamar_groq(prompt, _SYSTEM_PROMPT_JUIZ, temperature=0.0, origem="juiz_ordem_narrativa")
        data = json.loads(extrair_json(raw))
        return AvaliacaoOrdemNarrativa(
            ordem_correta=bool(data.get("ordem_correta", False)),
            justificativa=data.get("justificativa", ""),
        )
    except Exception as exc:
        print(f"  [AVISO juiz ordem narrativa] {exc}", file=sys.stderr)
        return AvaliacaoOrdemNarrativa(ordem_correta=None, erro=str(exc))
