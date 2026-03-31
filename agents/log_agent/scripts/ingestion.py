import json
import pandas as pd
from src.core.embedder import LogEmbedder
from src.services.qdrant_client import QdrantManager
from qdrant_client.http import models
import uuid

class MitreIngestor:
    def __init__(self):
        self.embedder = LogEmbedder()
        self.qdrant = QdrantManager()

    def ingest_from_file(self, file_path):
        print(f"📂 Lendo dataset: {file_path}")
        
        # Suporta JSON ou CSV
        if file_path.endswith('.json'):
            with open(file_path, 'r') as f:
                data = json.load(f)
            # Ajuste o mapeamento abaixo conforme a estrutura do seu JSON
            df = pd.DataFrame(data) 
        else:
            df = pd.read_csv(file_path)

        points = []
        print(f"🧠 Vetorizando {len(df)} técnicas... Isso pode levar um tempo no seu Fedora.")

        for _, row in df.iterrows():
            # O campo 'text_to_vector' deve ser a descrição técnica ou exemplos de comandos
            # O BERT funciona melhor com descrições ricas em contexto
            text_content = f"{row['technique_name']}: {row['description']}"
            
            vector = self.embedder.get_vector(text_content)
            
            points.append(
                models.PointStruct(
                    id=str(uuid.uuid4()),
                    vector=vector,
                    payload={
                        "name": row['technique_name'],
                        "id": row['external_id'], # Ex: T1053
                        "tactic": row['tactic'],
                        "suggestion": row['mitigation_steps'],
                        "description": row['description']
                    }
                )
            )

        # Upsert em lotes de 100 para não sobrecarregar a memória
        for i in range(0, len(points), 100):
            batch = points[i:i + 100]
            self.qdrant.client.upsert(
                collection_name=self.qdrant.collection_name,
                points=batch
            )
        
        print(f"✅ Sucesso! {len(points)} técnicas integradas ao SOAR.")

if __name__ == "__main__":
    ingestor = MitreIngestor()
    # Exemplo: você baixa o csv do MITRE e aponta o caminho aqui
    ingestor.ingest_from_file("data/mitre_attack_linux.csv")