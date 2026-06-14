"""
retriever/semantic_retriever.py

Recuperador semântico: recebe um trecho de log (ou descrição de comportamento)
e retorna as técnicas MITRE ATT&CK mais similares armazenadas no Qdrant.

Uso standalone:
    python retriever/semantic_retriever.py \
        --query "sshd: failed password for root from 198.51.100.7" \
        --top-k 5
"""
from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from sentence_transformers import SentenceTransformer

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from services.qdrant_config import COLECAO_PRINCIPAL, obter_cliente_qdrant

# ---------------------------------------------------------------------------
# Configurações
# ---------------------------------------------------------------------------
MODELO_EMBEDDING = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
TOP_K_PADRAO = int(os.getenv("RETRIEVER_TOP_K", "2"))
LIMIAR_SCORE = float(os.getenv("RETRIEVER_SCORE_THRESHOLD", "0.8"))


# ---------------------------------------------------------------------------
# Dataclass de resultado
# ---------------------------------------------------------------------------
@dataclass
class ResultadoBusca:
    tecnica_id: str
    nome_tecnica: str
    tatica: str
    tatica_id: str
    score: float                          # similaridade coseno [0, 1]
    descricao_mitre: str
    descricao_semantica_log: str
    plataformas_mitre: list[str]
    severidade_sugerida: str
    confianca_padrao: float
    palavras_chave_filtro: list[str]
    padroes_log: list[dict]
    texto_original_chunk: str = ""

    @property
    def score_combinado(self) -> float:
        """Score final = similaridade vetorial × confiança do padrão gerado."""
        return round(self.score * self.confianca_padrao, 4)

    def resumo(self) -> str:
        return (
            f"[{self.score:.3f}] {self.tecnica_id} — {self.nome_tecnica}\n"
            f"  Tática  : {self.tatica} ({self.tatica_id})\n"
            f"  Severidade: {self.severidade_sugerida.upper()}\n"
            f"  Score combinado: {self.score_combinado}\n"
            f"  Plataformas: {', '.join(self.plataformas_mitre) or 'N/A'}\n"
            f"  Desc.: {self.descricao_semantica_log[:120]}…"
        )


# ---------------------------------------------------------------------------
# Retriever principal
# ---------------------------------------------------------------------------
class RetrieverSemantico:
    """
    Encapsula o encoder e o cliente Qdrant para buscas reutilizáveis.

    Instancie uma vez e reutilize — o modelo de embedding é carregado na
    memória apenas no primeiro uso (lazy loading).
    """

    def __init__(
        self,
        modelo: str = MODELO_EMBEDDING,
        top_k: int = TOP_K_PADRAO,
        limiar_score: float = LIMIAR_SCORE,
    ) -> None:
        self.top_k = top_k
        self.limiar_score = limiar_score
        self._modelo_nome = modelo
        self._encoder: Optional[SentenceTransformer] = None
        self._cliente = obter_cliente_qdrant()

    # ------------------------------------------------------------------
    # Lazy loading do encoder
    # ------------------------------------------------------------------
    @property
    def encoder(self) -> SentenceTransformer:
        if self._encoder is None:
            print(f"[*] Carregando modelo de embeddings '{self._modelo_nome}'…")
            self._encoder = SentenceTransformer(self._modelo_nome)
        return self._encoder

    # ------------------------------------------------------------------
    # Busca principal
    # ------------------------------------------------------------------
    def buscar(
        self,
        query: str,
        top_k: Optional[int] = None,
        limiar_score: Optional[float] = None,
        filtros: Optional[dict] = None,
    ) -> list[ResultadoBusca]:
        
        k = top_k or self.top_k
        threshold = limiar_score if limiar_score is not None else self.limiar_score

        vetor_query = self.encoder.encode(query).tolist()

        # Monta filtro Qdrant se fornecido
        qdrant_filter = None
        if filtros:
            from qdrant_client.models import Filter, FieldCondition, MatchValue
            conditions = [
                FieldCondition(key=chave, match=MatchValue(value=valor))
                for chave, valor in filtros.items()
            ]
            qdrant_filter = Filter(must=conditions)

        hits = self._cliente.query_points(
            collection_name=COLECAO_PRINCIPAL,
            query=vetor_query,
            limit=k,
            query_filter=qdrant_filter,
            with_payload=True,
            score_threshold=threshold,
        )

        # ... (Linhas 121-128: chamada query_points) ...
        
        resultados = []
        hits_reais = hits.points if hasattr(hits, "points") else hits
        
        for item in hits_reais:
            if isinstance(item, list):
                if not item:
                    continue
                hit_real = item[0]
            else:
                hit_real = item[1] if isinstance(item, tuple) else item
            
            # 🚨 TRAVA DE SEGURANÇA LOCAL:
            # Se o hit real for um objeto com atributo 'score', extraímos. Se for dict, usamos .get()
            score_ponto = hit_real.score if hasattr(hit_real, 'score') else getattr(hit_real, 'score', 0.0)
            if isinstance(hit_real, dict):
                score_ponto = hit_real.get("score", 0.0)

            # Se o score que voltou do banco for menor do que o limiar (0.8), 
            # nós barramos ele aqui no código. Ele não entra no relatório de jeito nenhum!
            if score_ponto < threshold:
                continue
                
            resultados.append(self._hit_para_resultado(hit_real))

        return resultados

    def buscar_por_keywords(
        self,
        keywords: list[str],
        top_k: Optional[int] = None,
    ) -> list[ResultadoBusca]:
        
        from qdrant_client.models import Filter, FieldCondition, MatchAny

        k = top_k or self.top_k

        qdrant_filter = Filter(
            must=[
                FieldCondition(
                    key="palavras_chave_filtro",
                    match=MatchAny(any=keywords),
                )
            ]
        )

        # Busca por scroll (sem vetor) para recuperar pontos por payload
        pontos, _ = self._cliente.scroll(
            collection_name=COLECAO_PRINCIPAL,
            scroll_filter=qdrant_filter,
            limit=k,
            with_payload=True,
            with_vectors=False,
        )

        resultados = []
        for ponto in pontos:
            p = ponto.payload or {}
            resultados.append(
                ResultadoBusca(
                    tecnica_id=p.get("tecnica_id", ""),
                    nome_tecnica=p.get("nome_tecnica", ""),
                    tatica=p.get("tatica", ""),
                    tatica_id=p.get("tatica_id", ""),
                    score=0.8,
                    descricao_mitre=p.get("descricao_mitre", ""),
                    descricao_semantica_log=p.get("descricao_semantica_log", ""),
                    plataformas_mitre=p.get("plataformas_mitre", []),
                    severidade_sugerida=p.get("severidade_sugerida", "medium"),
                    confianca_padrao=p.get("confianca_padrao", 0.9),
                    palavras_chave_filtro=p.get("palavras_chave_filtro", []),
                    padroes_log=p.get("padroes_log", []),
                    texto_original_chunk=p.get("texto_original_chunk", ""),
                )
            )
        return resultados

    def buscar_hibrido(
        self,
        query: str,
        keywords: list[str],
        top_k: Optional[int] = None,
        limiar_score: Optional[float] = None,
        filtros: Optional[dict] = None,
    ) -> list[ResultadoBusca]:
        
        semanticos = {
            r.tecnica_id: r
            for r in self.buscar(query, top_k=top_k, limiar_score=limiar_score, filtros=filtros)
        }
        lexicais = {
            r.tecnica_id: r
            for r in self.buscar_por_keywords(keywords, top_k=top_k)
            if r.tecnica_id not in semanticos
        }
        combinados = list(semanticos.values()) + list(lexicais.values())
        return sorted(combinados, key=lambda r: r.score_combinado, reverse=True)

    # ------------------------------------------------------------------
    # Helpers internos
    # ------------------------------------------------------------------
    @staticmethod
    def _hit_para_resultado(hit) -> ResultadoBusca:
        p = hit.payload or {}
        return ResultadoBusca(
            tecnica_id=p.get("tecnica_id", ""),
            nome_tecnica=p.get("nome_tecnica", ""),
            tatica=p.get("tatica", ""),
            tatica_id=p.get("tatica_id", ""),
            score=round(hit.score, 4),
            descricao_mitre=p.get("descricao_mitre", ""),
            descricao_semantica_log=p.get("descricao_semantica_log", ""),
            plataformas_mitre=p.get("plataformas_mitre", []),
            severidade_sugerida=p.get("severidade_sugerida", "medium"),
            confianca_padrao=p.get("confianca_padrao", 0.9),
            palavras_chave_filtro=p.get("palavras_chave_filtro", []),
            padroes_log=p.get("padroes_log", []),
            texto_original_chunk=p.get("texto_original_chunk", ""),
        )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Busca semântica de técnicas MITRE ATT&CK por trecho de log."
    )
    parser.add_argument("--query", "-q", required=True, help="Trecho de log ou comportamento.")
    parser.add_argument("--top-k", "-k", type=int, default=TOP_K_PADRAO)
    parser.add_argument("--threshold", "-t", type=float, default=LIMIAR_SCORE)
    parser.add_argument(
        "--modo",
        choices=["semantico", "hibrido"],
        default="semantico",
        help="Modo de busca (padrão: semantico).",
    )
    parser.add_argument(
        "--keywords",
        nargs="*",
        default=[],
        help="Keywords adicionais para modo híbrido.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    retriever = RetrieverSemantico(top_k=args.top_k, limiar_score=args.threshold)

    if args.modo == "hibrido":
        resultados = retriever.buscar_hibrido(
            args.query, args.keywords, top_k=args.top_k, limiar_score=args.threshold
        )
    else:
        resultados = retriever.buscar(args.query, top_k=args.top_k, limiar_score=args.threshold)

    if not resultados:
        print("[-] Nenhuma técnica encontrada acima do limiar de score.")
        return

    print(f"\n[+] {len(resultados)} técnica(s) encontrada(s):\n")
    for i, r in enumerate(resultados, 1):
        print(f"--- #{i} ---")
        print(r.resumo())
        print()


if __name__ == "__main__":
    main()