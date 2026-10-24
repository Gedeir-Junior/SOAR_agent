# log-agent/services/qdrant_config.py
import os
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams

COLECAO_PRINCIPAL = "colecao_logs_patterns"
DIMENSAO_VETOR = 384

def obter_cliente_qdrant() -> QdrantClient:
    qdrant_url = os.getenv("QDRANT_URL", "http://localhost:6333")
    try:
        client = QdrantClient(url=qdrant_url, timeout=10)
        return client
    except Exception as e:
        raise RuntimeError(f"Erro ao conectar no servidor Qdrant em {qdrant_url}: {e}")

def configurar_colecao(client: QdrantClient, forcar_recriacao: bool = False):

    try:
        existe = client.collection_exists(collection_name=COLECAO_PRINCIPAL)
        
        if existe and not forcar_recriacao:
            print(f"[+] A coleção '{COLECAO_PRINCIPAL}' já existe. Pronto para uso.")
            return
            
        if existe and forcar_recriacao:
            print(f"[*] Apagando coleção antiga '{COLECAO_PRINCIPAL}' para recriação...")
            

        client.recreate_collection(
            collection_name=COLECAO_PRINCIPAL,
            vectors_config=VectorParams(
                size=DIMENSAO_VETOR, 
                distance=Distance.COSINE
            ),
        )
        print(f"[+] Coleção '{COLECAO_PRINCIPAL}' configurada com sucesso (Métrica: COSSENO, Dimensões: {DIMENSAO_VETOR}).")
        
    except Exception as e:
        raise RuntimeError(f"Falha ao configurar a coleção no Qdrant: {e}")