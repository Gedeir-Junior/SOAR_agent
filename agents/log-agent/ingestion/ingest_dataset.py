import json
import uuid
import os
import sys
from pathlib import Path
from qdrant_client.models import PointStruct
from sentence_transformers import SentenceTransformer

# 1. Ajuste do caminho base: sobe duas pastas para sair de 'ingestion/' e chegar na raiz do projeto
BASE_DIR = Path(__file__).resolve().parent.parent
DATASETS_DIR = BASE_DIR / "datasets"

# 2. Garante que o Python consiga enxergar a pasta 'services/' a partir da pasta 'ingestion/'
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Agora o import vai funcionar perfeitamente sem dar ModuleNotFoundError
from services.qdrant_config import obter_cliente_qdrant, configurar_colecao, COLECAO_PRINCIPAL

def processar_e_ingestao_datasets():
    print("[*] Carregando modelo de embeddings na memória...")
    encoder = SentenceTransformer("all-MiniLM-L6-v2")

    qdrant_client = obter_cliente_qdrant()
    
    # Executa a configuração da coleção antes de ler os arquivos
    configurar_colecao(qdrant_client, forcar_recriacao=True)

    arquivos_json = list(DATASETS_DIR.glob("*.json"))
    if not arquivos_json:
        print(f"[-] Nenhum arquivo dataset encontrado em: {DATASETS_DIR}")
        return

    points_batch = []

    for arquivo in arquivos_json:
        if arquivo.name == "manifest.json":
            continue
            
        print(f"[*] Processando arquivo de tática: {arquivo.name}...")
        with arquivo.open("r", encoding="utf-8") as f:
            tactic_data = json.load(f)
            
        for padrao in tactic_data.get("padroes", []):
            texto_chunk = padrao.get("texto_busca_vetorial")
            if not texto_chunk:
                continue
                
            vetor_chunk = encoder.encode(texto_chunk).tolist()
            
            payload_dados = {
                "tecnica_id": padrao.get("tecnica_id"),
                "nome_tecnica": padrao.get("nome_tecnica"),
                "tatica": padrao.get("tatica"),
                "tatica_id": padrao.get("tatica_id"),
                "descricao_mitre": padrao.get("descricao_mitre"),
                "descricao_semantica_log": padrao.get("descricao_semantica_log"),
                "plataformas_mitre": padrao.get("plataformas_mitre", []),
                "padroes_log": padrao.get("padroes_log", []),
                "palavras_chave_filtro": padrao.get("palavras_chave_filtro", []),
                "severidade_sugerida": padrao.get("severidade_sugerida", "medium"),
                "confianca_padrao": padrao.get("confianca_padrao", 0.7),
                "texto_original_chunk": texto_chunk
            }
            
            point_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, padrao.get("tecnica_id")))
            
            points_batch.append(
                PointStruct(id=point_id, vector=vetor_chunk, payload=payload_dados)
            )

    if points_batch:
        print(f"[*] Fazendo upload de {len(points_batch)} técnicas para o Qdrant...")
        qdrant_client.upsert(collection_name=COLECAO_PRINCIPAL, points=points_batch)
        print(f"[+] Ingestão concluída com sucesso na coleção '{COLECAO_PRINCIPAL}'!")

if __name__ == "__main__":
    processar_e_ingestao_datasets()