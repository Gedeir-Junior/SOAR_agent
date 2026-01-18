import os
from sentece_transformers import SentenceTransformer
import numpy as np

# Configuration

EMBEDDING_MODEL = os.getenv(
    "EMBEDDING_MODEL",
    "sentence-transformers/all-MiniLM-L6-v2"
    )

NORMALIZE_EMBEDDINGS = os.getenv("NORMALIZE_EMBEDDINGS", "true").lower() == "true"

# Load the embedding model

_model = SentenceTransformer(EMBEDDING_MODEL)

# API

def embed(texts: list[str]) -> np.ndarray:
    """
    Gera embeddings para uma lista de textos.
    """
    if not texts:
        raise ValueError("A lista de textos está vazia.")
    
    vectors = _model.encode(texts, convert_to_numpy=True, normalize_embeddings=NORMALIZE_EMBEDDINGS)
    return vectors

def embed_text(text: str) -> np.ndarray:
    """
    Gera um embedding para um único texto.
    """
    if not text or not text.strip():
        raise ValueError("O texto está vazio para embedding.")
    
    vector = _model.encode([text], convert_to_numpy=True, normalize_embeddings=NORMALIZE_EMBEDDINGS)[0]
    return vector