"""
pipeline_contextual/agente_organizador_fases.py

Stage 2 (reduce) do pipeline contextual.

Consolida a lista ordenada de ResumoChunk em FaseComportamental[] ordenadas,
agrupando trechos com o mesmo padrão de comportamento e separando fases quando
o comportamento muda (ex: reconhecimento -> login suspeito -> persistência).

Hierárquico: se o número de itens exceder CONTEXTUAL_REDUCE_BATCH_SIZE, particiona
em lotes, reduz cada lote a sub-fases e repete o processo sobre as sub-fases
resultantes, até caber em uma única chamada final ao LLM.

Trava de segurança: linha_inicio/linha_fim de cada fase são sempre recalculados
no código (min/max das linhas dos itens de origem), nunca aceitos como o LLM os
retornou. numero_fase é renumerado sequencialmente por linha_inicio ao final de
cada consolidação.
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
from pipeline_contextual.agente_resumidor_arquivo import ResumoChunk

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
CONTEXTUAL_REDUCE_BATCH_SIZE = int(os.getenv("CONTEXTUAL_REDUCE_BATCH_SIZE", "20"))

_SYSTEM_PROMPT = (
    "Você é um analista de segurança sênior especializado em resposta a incidentes. "
    "Sua tarefa é organizar uma sequência cronológica de resumos de log em fases "
    "comportamentais ordenadas, agrupando trechos com o mesmo padrão de comportamento "
    "e separando quando o comportamento muda claramente (ex: reconhecimento -> "
    "exploração -> persistência -> exfiltração). "
    "Responda SOMENTE com JSON válido, sem markdown nem explicações."
)

_SEVERIDADE_ORDEM = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ---------------------------------------------------------------------------
# Dataclass de saída
# ---------------------------------------------------------------------------
@dataclass
class FaseComportamental:
    numero_fase: int
    linha_inicio: int
    linha_fim: int
    titulo_fase: str
    descricao_comportamental: str          # usado como query na busca semântica
    entidades_identificadas: list[str] = field(default_factory=list)
    severidade_inferida: str = "info"
    chunks_origem: list[int] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Representação interna normalizada (chunks ou sub-fases de nível anterior)
# ---------------------------------------------------------------------------
@dataclass
class _ItemReduzivel:
    id_local: int              # id usado apenas dentro desta chamada ao LLM
    linha_inicio: int
    linha_fim: int
    texto: str
    entidades: list[str]
    severidade: str
    chunks_origem: list[int]   # números de chunk ORIGINAIS cobertos por este item


def _normalizar_chunks(resumos: list[ResumoChunk]) -> list[_ItemReduzivel]:
    return [
        _ItemReduzivel(
            id_local=r.numero_chunk,
            linha_inicio=r.linha_inicio,
            linha_fim=r.linha_fim,
            texto=r.resumo_comportamental,
            entidades=list(r.entidades_identificadas),
            severidade=r.severidade_maxima,
            chunks_origem=[r.numero_chunk],
        )
        for r in resumos
    ]


def _normalizar_fases(fases: list[FaseComportamental]) -> list[_ItemReduzivel]:
    return [
        _ItemReduzivel(
            id_local=f.numero_fase,
            linha_inicio=f.linha_inicio,
            linha_fim=f.linha_fim,
            texto=f"{f.titulo_fase}: {f.descricao_comportamental}",
            entidades=list(f.entidades_identificadas),
            severidade=f.severidade_inferida,
            chunks_origem=list(f.chunks_origem),
        )
        for f in fases
    ]


# ---------------------------------------------------------------------------
# Construção e parsing do prompt de consolidação
# ---------------------------------------------------------------------------
def _build_prompt_reduce(itens: list[_ItemReduzivel]) -> str:
    bloco = "\n".join(
        f"[{it.id_local}] (linhas {it.linha_inicio}-{it.linha_fim}, severidade={it.severidade}): {it.texto}"
        for it in itens
    )
    ids_disponiveis = ", ".join(str(it.id_local) for it in itens)
    return f"""Você recebeu {len(itens)} resumos ordenados cronologicamente de um arquivo de log.
Cada resumo tem um identificador entre colchetes.

Agrupe-os em fases comportamentais distintas, respeitando a ordem cronológica.
Crie uma nova fase somente quando o comportamento muda claramente. Resumos
consecutivos com o mesmo padrão de comportamento devem ficar na mesma fase.

Retorne SOMENTE este JSON:
{{
  "fases": [
    {{
      "titulo_fase": "<título curto, ex: 'Reconhecimento de rede'>",
      "descricao_comportamental": "<3-6 frases descrevendo o comportamento da fase, adequada para busca semântica>",
      "entidades_identificadas": ["<entidades relevantes da fase>"],
      "severidade_inferida": "<info | low | medium | high | critical>",
      "chunks_origem": [<ids inteiros usados apenas dentre: {ids_disponiveis}>]
    }}
  ]
}}

Critérios:
- Use APENAS os identificadores fornecidos em chunks_origem — nunca invente números.
- Todo identificador de entrada deve aparecer em exatamente uma fase de saída.
- Mantenha a ordem cronológica das fases no array de saída.

Resumos:
{bloco}
"""


def _parsear_resposta_reduce(raw: str, itens: list[_ItemReduzivel]) -> list[FaseComportamental]:
    data = json.loads(extrair_json(raw))
    fases_raw = data.get("fases", [])
    itens_por_id = {it.id_local: it for it in itens}

    fases: list[FaseComportamental] = []
    ids_usados: set[int] = set()

    for fase_raw in fases_raw:
        # Cada id só pode pertencer à primeira fase que o reivindicar — o LLM às
        # vezes viola a instrução do prompt e reutiliza o mesmo chunk_origem em
        # várias fases (fabricando subdivisões dentro de um único resumo já
        # condensado). Ignorar reivindicações repetidas evita fases fantasmas
        # com o mesmo intervalo de linhas e queries de busca desconectadas do
        # conteúdo real.
        ids_referenciados = [
            i for i in fase_raw.get("chunks_origem", [])
            if i in itens_por_id and i not in ids_usados
        ]
        if not ids_referenciados:
            continue

        ids_usados.update(ids_referenciados)
        referenciados = [itens_por_id[i] for i in ids_referenciados]

        chunks_origem_acumulados = sorted({c for it in referenciados for c in it.chunks_origem})
        entidades = sorted({e for it in referenciados for e in it.entidades})
        severidade_max = max(
            (it.severidade for it in referenciados),
            key=lambda s: _SEVERIDADE_ORDEM.get(s, 0),
        )

        fases.append(FaseComportamental(
            numero_fase=0,  # renumerado ao final desta consolidação
            linha_inicio=min(it.linha_inicio for it in referenciados),
            linha_fim=max(it.linha_fim for it in referenciados),
            titulo_fase=fase_raw.get("titulo_fase", "Fase sem título"),
            descricao_comportamental=fase_raw.get("descricao_comportamental", ""),
            entidades_identificadas=entidades,
            severidade_inferida=fase_raw.get("severidade_inferida", severidade_max),
            chunks_origem=chunks_origem_acumulados,
        ))

    # Trava de segurança: itens não referenciados pelo LLM (omissão de
    # consolidação) viram uma fase residual própria — nunca são descartados.
    ids_faltantes = [it.id_local for it in itens if it.id_local not in ids_usados]
    if ids_faltantes:
        print(
            f"  [AVISO organizador] {len(ids_faltantes)} item(ns) não classificados "
            f"pelo LLM — agrupando em fase residual."
        )
        faltantes = [itens_por_id[i] for i in ids_faltantes]
        fases.append(FaseComportamental(
            numero_fase=0,
            linha_inicio=min(it.linha_inicio for it in faltantes),
            linha_fim=max(it.linha_fim for it in faltantes),
            titulo_fase="Eventos não classificados",
            descricao_comportamental=" ".join(it.texto for it in faltantes)[:1000],
            entidades_identificadas=sorted({e for it in faltantes for e in it.entidades}),
            severidade_inferida=max(
                (it.severidade for it in faltantes),
                key=lambda s: _SEVERIDADE_ORDEM.get(s, 0),
            ),
            chunks_origem=sorted({c for it in faltantes for c in it.chunks_origem}),
        ))

    fases.sort(key=lambda f: f.linha_inicio)
    for idx, fase in enumerate(fases, 1):
        fase.numero_fase = idx

    return fases


# ---------------------------------------------------------------------------
# Agente principal
# ---------------------------------------------------------------------------
class AgenteOrganizadorFases:
    """
    Stage 2 (reduce) do pipeline contextual: consolida ResumoChunk[] em
    FaseComportamental[] ordenadas, com reduce hierárquico para arquivos grandes.
    """

    def __init__(self, reduce_batch_size: int = CONTEXTUAL_REDUCE_BATCH_SIZE) -> None:
        self.reduce_batch_size = reduce_batch_size

    def organizar(self, resumos: list[ResumoChunk]) -> list[FaseComportamental]:
        if not resumos:
            print("[*] Organizador: nenhum resumo para consolidar.")
            return []

        itens = _normalizar_chunks(resumos)
        nivel = 1

        while len(itens) > self.reduce_batch_size:
            print(
                f"[*] Organizador: nível {nivel} — reduzindo {len(itens)} item(ns) "
                f"em lotes de {self.reduce_batch_size}…"
            )
            fases_intermediarias = self._reduzir_em_lotes(itens)
            itens = _normalizar_fases(fases_intermediarias)
            nivel += 1

        print(f"[*] Organizador: consolidação final de {len(itens)} item(ns) em fases…")
        fases_finais = self._reduzir_lote_unico(itens)

        print(f"[+] Organizador concluído: {len(fases_finais)} fase(s) identificada(s).")
        return fases_finais

    def _reduzir_em_lotes(self, itens: list[_ItemReduzivel]) -> list[FaseComportamental]:
        """Reduz cada lote de `reduce_batch_size` itens independentemente,
        renumerando sequencialmente entre lotes para evitar colisão de
        numero_fase quando o resultado virar entrada do próximo nível."""
        resultado: list[FaseComportamental] = []
        offset = 0
        for i in range(0, len(itens), self.reduce_batch_size):
            lote = itens[i : i + self.reduce_batch_size]
            fases_lote = self._reduzir_lote_unico(lote)
            for fase in fases_lote:
                fase.numero_fase += offset
            offset += len(fases_lote)
            resultado.extend(fases_lote)
        return resultado

    def _reduzir_lote_unico(self, itens: list[_ItemReduzivel]) -> list[FaseComportamental]:
        try:
            raw = chamar_groq(
                _build_prompt_reduce(itens),
                _SYSTEM_PROMPT,
                temperature=0.15,
                origem="organizador",
            )
            return _parsear_resposta_reduce(raw, itens)
        except Exception as exc:
            print(f"  [ERRO organizador] {exc}", file=sys.stderr)
            # Fallback: cada item vira sua própria fase — garante que nada se perde.
            return [
                FaseComportamental(
                    numero_fase=idx,
                    linha_inicio=it.linha_inicio,
                    linha_fim=it.linha_fim,
                    titulo_fase=f"Trecho linhas {it.linha_inicio}-{it.linha_fim}",
                    descricao_comportamental=it.texto,
                    entidades_identificadas=list(it.entidades),
                    severidade_inferida=it.severidade,
                    chunks_origem=list(it.chunks_origem),
                )
                for idx, it in enumerate(itens, 1)
            ]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    import dataclasses

    parser = argparse.ArgumentParser(description="Consolida ResumoChunk[] em fases comportamentais.")
    parser.add_argument("resumos_json", type=Path, help="JSON de saída do agente resumidor.")
    parser.add_argument("--reduce-batch-size", type=int, default=CONTEXTUAL_REDUCE_BATCH_SIZE)
    parser.add_argument("--saida", type=Path, default=None)
    args = parser.parse_args()

    dados = json.loads(args.resumos_json.read_text(encoding="utf-8"))
    resumos = [ResumoChunk(**d) for d in dados]

    agente = AgenteOrganizadorFases(reduce_batch_size=args.reduce_batch_size)
    fases = agente.organizar(resumos)

    for f in fases:
        print(f"Fase {f.numero_fase} (L{f.linha_inicio}-{f.linha_fim}) [{f.severidade_inferida.upper()}] {f.titulo_fase}")

    if args.saida:
        args.saida.write_text(
            json.dumps([dataclasses.asdict(f) for f in fases], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"\n[+] Fases salvas em: {args.saida}")
