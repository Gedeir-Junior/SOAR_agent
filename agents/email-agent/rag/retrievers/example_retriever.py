from pathlib import Path
from rag.retrievers.base import FaissRetriever

BASE_DIR = Path(__file__).resolve().parents[2]
EXAMPLE_STORE = BASE_DIR / "rag" / "vectorstore" / "examples"

_example_retriever = FaissRetriever(EXAMPLE_STORE)


def retrieve_examples(query: str, k: int = 5):
    return _example_retriever.search(query, k)
