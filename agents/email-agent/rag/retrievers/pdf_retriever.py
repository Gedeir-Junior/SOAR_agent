from pathlib import Path
from rag.retrievers.base import FaissRetriever

BASE_DIR = Path(__file__).resolve().parent.parent
PDF_STORE = BASE_DIR / "vectorstore" / "guides"

_pdf_retriever = FaissRetriever(PDF_STORE)

def retrieve_pdf_context(query: str, k: int = 5) -> str:
    docs = _pdf_retriever.search(query, k)
    return "\n\n".join(d["text"] for d in docs)

