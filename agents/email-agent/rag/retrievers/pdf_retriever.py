from pathlib import Path
from rag.retrievers.base import FaissRetriever

BASE_DIR = Path(__file__).resolve().parent.parent
PDF_STORE = BASE_DIR / "vectorstore" / "guides"

_pdf_retriever = FaissRetriever(PDF_STORE)

def retrieve_pdf_context(query: str, k: int = 5) -> str:
    docs = _pdf_retriever.search(query, k)
    # Inclui a fonte no contexto enviado para a LLM
    return "\n\n".join(f"[Fonte: {d['metadata']['source']}] {d['text']}" for d in docs)
