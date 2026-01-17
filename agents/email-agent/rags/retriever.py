import pickle
import numpy as np
import faiss
from pathlib import Path

from rags.embeddings import embed_text

BASE_DIR = Path(__file__).parent
VECTORSTORE_PATH = BASE_DIR / "vectorstore"

CHUNKS_PATH = VECTORSTORE_PATH / "chunks.pkl"
INDEX_PATH = VECTORSTORE_PATH / "index.faiss"

if not CHUNKS_PATH.exists() or not INDEX_PATH.exists():
    raise RuntimeError(
        "Vectorstore não encontrado. Execute `python -m rags.ingest` antes."
    )

with open(CHUNKS_PATH, "rb") as f:
    CHUNKS = pickle.load(f)

INDEX = faiss.read_index(str(INDEX_PATH))


def retrieve(query: str, k: int = 5):
    query_vector = embed_text(query)
    query_vector = np.array([query_vector]).astype("float32")

    distances, indices = INDEX.search(query_vector, k)

    return [CHUNKS[i] for i in indices[0] if i < len(CHUNKS)]


def get_reference_material(query: str, top_k: int = 5) -> str:
    docs = retrieve(query, k=top_k)
    return "\n\n".join(docs)
