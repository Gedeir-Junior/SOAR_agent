from pathlib import Path
import csv
import sys
import json
import faiss
import numpy as np
from itertools import islice
from rag.embeddings import embed

# Configuração de segurança para campos longos
csv.field_size_limit(sys.maxsize)

# Definição de Caminhos
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATASETS_DIR = BASE_DIR / "datasets"
VECTORSTORE_DIR = BASE_DIR / "rag" / "vectorstore" / "examples"
VECTORSTORE_DIR.mkdir(parents=True, exist_ok=True)

# Configurações de Colunas e Limites
TEXT_COLUMN = ["subject", "body", "text", "content", "message"]
LABEL_COLUMN = ["label", "class", "category", "spam"]
MAX_SAMPLES_PER_FILE = 500  # Limite para não estourar a RAM
BATCH_SIZE = 50             # Processar embeddings de 50 em 50

def detect_column(columns, candidates):
    for candidate in candidates:
        if candidate in columns:
            return candidate
    return None

def ingest_csv():
    all_chunks = []
    
    # Busca por arquivos .csv (case-insensitive)
    csv_files = [f for f in DATASETS_DIR.glob("*.csv")]
    
    if not csv_files:
        print(f"Erro: Nenhum arquivo CSV encontrado em {DATASETS_DIR}")
        return

    for csv_file in csv_files:
        if csv_file.stat().st_size == 0:
            print(f"Pulando arquivo vazio: {csv_file.name}")
            continue
        
        print(f"Iniciando leitura de: {csv_file.name}")
        with open(csv_file, newline="", encoding="utf-8", errors="ignore") as f:
            # O DictReader por padrão usa vírgula, o que está correto para o seu arquivo
            reader = csv.DictReader(f)
            
            for row in islice(reader, MAX_SAMPLES_PER_FILE):
                subject = row.get("subject", "").strip()
                body = row.get("body", "").strip()
                sender = row.get("sender", "").strip()
                receiver = row.get("receiver", "").strip()
                urls = row.get("urls", "").strip()
                label_raw = row.get("label", "0").strip()
                
                # Texto principal para o Embedding (busca semântica)
                # Incluímos o Sender e Subject no corpo do texto para busca
                combined_text = f"From: {sender}\nSubject: {subject}\nBody: {body}"
                
                label_desc = "phishing" if label_raw == "1" else "legitimate"

                if len(body) > 10:
                    all_chunks.append({
                        "text": combined_text,
                        "metadata": {
                            "source": csv_file.name,
                            "sender": sender,
                            "receiver": receiver,
                            "urls": urls,
                            "label": label_desc,
                            "type": "email_example"
                        }
                    })

    if not all_chunks:
        raise RuntimeError("Nenhum dado válido encontrado nos datasets CSV.")
    
    print(f"Total de {len(all_chunks)} exemplos carregados. Gerando embeddings em lotes...")
    
    # Extração de textos e geração de embeddings em lotes para economizar RAM
    texts = [c["text"] for c in all_chunks]
    all_embeddings = []
    
    for i in range(0, len(texts), BATCH_SIZE):
        batch = texts[i:i + BATCH_SIZE]
        print(f"Processando lote {i//BATCH_SIZE + 1}...")
        batch_embeddings = embed(batch)
        all_embeddings.append(batch_embeddings)
    
    embeddings = np.vstack(all_embeddings).astype("float32")

    # Criação do índice FAISS
    index = faiss.IndexFlatL2(embeddings.shape[1])
    index.add(embeddings)

    # Salvando os arquivos finais
    with open(VECTORSTORE_DIR / "chunks.json", "w", encoding="utf-8") as f:
        json.dump(all_chunks, f, ensure_ascii=False, indent=2)

    faiss.write_index(index, str(VECTORSTORE_DIR / "index.faiss"))
    
    print(f"✅ Ingest concluído: {len(all_chunks)} exemplos processados com sucesso!")

if __name__ == "__main__":
    ingest_csv()