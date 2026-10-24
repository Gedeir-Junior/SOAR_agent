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

# Técnicas cuja própria descrição admite não gerar evidência observável em log
# (OSINT passivo, staging de infraestrutura do atacante etc.) não devem competir
# no índice vetorial: seu texto usa vocabulário genérico de "ataque externo" que
# vence buscas de outras táticas (ex.: Initial Access) sem relação real com o
# log analisado. Ver achado da rodada de testes de fase única de 15/08/2026.
_MARCADORES_SEM_EVIDENCIA_LOG = [
    "nenhum log", "nenhuma conexao", "nenhuma conexão", "nenhum evento",
    "fora da rede", "fora do perimetro", "fora do perímetro",
    "sem qualquer interacao", "sem qualquer interação",
    "nao ha geracao", "não há geração", "nao gera", "não gera",
    "sem gerar log", "nao recebe nenhuma conexao", "não recebe nenhuma conexão",
]


def _gera_evidencia_observavel(descricao: str) -> bool:
    """False quando a própria descrição admite que a técnica não deixa rastro
    observável em log (ver _MARCADORES_SEM_EVIDENCIA_LOG)."""
    desc = (descricao or "").lower()
    return not any(marcador in desc for marcador in _MARCADORES_SEM_EVIDENCIA_LOG)


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
    total_pulados = 0

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

            if not _gera_evidencia_observavel(padrao.get("descricao_semantica_log", "")):
                total_pulados += 1
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
            
            chave_ponto = f"{padrao.get('tecnica_id')}::{padrao.get('tatica_id')}"
            point_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, chave_ponto))
            
            points_batch.append(
                PointStruct(id=point_id, vector=vetor_chunk, payload=payload_dados)
            )

    print(f"[*] {total_pulados} técnica(s) pulada(s) por não gerar evidência observável em log.")

    if points_batch:
        print(f"[*] Fazendo upload de {len(points_batch)} técnicas para o Qdrant...")
        qdrant_client.upsert(collection_name=COLECAO_PRINCIPAL, points=points_batch)
        print(f"[+] Ingestão concluída com sucesso na coleção '{COLECAO_PRINCIPAL}'!")

if __name__ == "__main__":
    processar_e_ingestao_datasets()