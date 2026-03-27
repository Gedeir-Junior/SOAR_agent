import uuid
from datetime import datetime
from qdrant_client import QdrantClient
from qdrant_client.http import models

class QdrantLogConnector:
    def __init__(self, host="qdrant", port=6333):
        self.client = QdrantClient(host=host, port=port)
        self.collection_name = "security_logs"
        self._ensure_collection_exists()

    def _ensure_collection_exists(self):
        collections = self.client.get_collections().collections
        exists = any(c.name == self.collection_name for c in collections)
        
        if not exists:
            self.client.create_collection(
                collection_name=self.collection_name,
                vectors_config=models.VectorParams(
                    size=768,
                    distance=models.Distance.COSINE
                ),
            )

    def save_anomaly(self, vector, log_text, metadata):
        point_id = str(uuid.uuid4())
        self.client.upsert(
            collection_name=self.collection_name,
            points=[
                models.PointStruct(
                    id=point_id,
                    vector=vector,
                    payload={
                        "raw_log": log_text,
                        "timestamp": datetime.now().isoformat(),
                        **metadata # Inclui user, ip, host, etc.
                    }
                )
            ]
        )
        return point_id

    def get_context_for_rag(self, target_vector, limit=5):
        search_result = self.client.search(
            collection_name=self.collection_name,
            query_vector=target_vector,
            limit=limit,
            with_payload=True
        )
        context = [res.payload['raw_log'] for res in search_result]
        return context