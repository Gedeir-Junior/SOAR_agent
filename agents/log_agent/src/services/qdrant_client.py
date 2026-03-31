from qdrant_client import QdrantClient
from qdrant_client.http import models
import uuid

class QdrantManager:
    def __init__(self, host="localhost", port=6333):
        self.client = QdrantClient(host=host, port=port)
        self.collection_name = "security_knowledge"
        self._bootstrap()

    def _bootstrap(self):
        # Garante que a coleção exista com 384 dimensões (MiniLM)
        collections = self.client.get_collections().collections
        if not any(c.name == self.collection_name for c in collections):
            self.client.create_collection(
                collection_name=self.collection_name,
                vectors_config=models.VectorParams(
                    size=384, 
                    distance=models.Distance.COSINE
                )
            )

    def search_threat(self, vector, threshold=0.90):
        """Busca se o log se parece com algum ataque do MITRE"""
        results = self.client.search(
            collection_name=self.collection_name,
            query_vector=vector,
            limit=1
        )
        if results and results[0].score >= threshold:
            return results[0].payload
        return None