import json
import faiss
import numpy as np
from pathlib import Path
from rag.embeddings import embed_text

class FaissRetriever:
    def __init__(self, vectorstore_path: Path):
        self.chunks_path = vectorstore_path / "chunks.json"
        self.index_path = vectorstore_path / "index.faiss"

        if not self.chunks_path.exists() or not self.index_path.exists():
            raise RuntimeError("Vectorstore files are missing.")
        
        with open(self.chunks_path, "r", encoding="utf-8") as f:
            self.chunks = json.load(f)
        
        self.index = faiss.read_index(str(self.index_path)) 

    def search(self, query: str, k:int = 5):
        vector = np.array([embed_text(query)]).astype("float32")
        distances, indices = self.index.search(vector, k)
        results = []
        for idx in indices[0]:
            if idx < len(self.chunks):
                results.append(self.chunks[idx])
        return results
