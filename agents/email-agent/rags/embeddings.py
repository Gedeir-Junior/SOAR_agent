from sentence_transformers import SentenceTransformer
import numpy as np

# Carregado uma única vez (import-time)
model = SentenceTransformer("all-MiniLM-L6-v2")

def embed(texts: list[str]) -> np.ndarray:
    """
    Gera embeddings para uma lista de textos (FAISS-friendly)
    """
    return model.encode(texts, convert_to_numpy=True)

def embed_text(text: str) -> list[float]:
    """
    Gera embedding para um único texto
    """
    return embed([text])[0].tolist()
