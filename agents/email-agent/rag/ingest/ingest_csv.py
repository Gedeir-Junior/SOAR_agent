from pathlib import Path
import csv
import sys
import json
import faiss
import numpy as np
from rag.embeddings import embed

# Configuração de limites do CSV
csv.field_size_limit(sys.maxsize)

# Configurações de diretórios
BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATASETS_DIR = BASE_DIR / "datasets"
VECTORSTORE_DIR = BASE_DIR / "rag" / "vectorstore" / "examples"
VECTORSTORE_DIR.mkdir(parents=True, exist_ok=True)

# PARÂMETROS DE BALANCEAMENTO
TOTAL_TARGET = 1000
TARGET_PER_CLASS = TOTAL_TARGET // 2  # 500 phishing, 500 legítimos
BATCH_SIZE = 50

def ingest_strictly_balanced():
    phishing_pool = []
    legitimate_pool = []
    
    csv_files = list(DATASETS_DIR.glob("*.csv"))
    if not csv_files:
        print(f"Erro: Nenhum CSV encontrado em {DATASETS_DIR}")
        return

    for csv_file in csv_files:
        print(f"🔍 Coletando amostras equilibradas de: {csv_file.name}")
        with open(csv_file, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # Critério de parada: Ambos os baldes estão cheios
                if len(phishing_pool) >= TARGET_PER_CLASS and len(legitimate_pool) >= TARGET_PER_CLASS:
                    break
                
                label_raw = row.get("label", "0").strip()
                label_desc = "phishing" if label_raw == "1" else "legitimate"
                
                # Dados para o chunk
                subject = row.get("subject", "").strip()
                body = row.get("body", "").strip()
                sender = row.get("sender", "").strip()
                combined_text = f"From: {sender}\nSubject: {subject}\nBody: {body}"

                if len(body) > 10:
                    chunk = {
                        "text": combined_text,
                        "metadata": {
                            "source": csv_file.name,
                            "label": label_desc,
                            "type": "email_example"
                        }
                    }
                    
                    # Adição seletiva para garantir o balanço
                    if label_desc == "phishing" and len(phishing_pool) < TARGET_PER_CLASS:
                        phishing_pool.append(chunk)
                    elif label_desc == "legitimate" and len(legitimate_pool) < TARGET_PER_CLASS:
                        legitimate_pool.append(chunk)

    # União e embaralhamento para evitar viés de ordem
    all_chunks = phishing_pool + legitimate_pool
    np.random.shuffle(all_chunks)

    print("\n" + "="*40)
    print(f"⚖️ RELATÓRIO DE BALANCEAMENTO")
    print(f"Phishing:   {len(phishing_pool)} / {TARGET_PER_CLASS}")
    print(f"Legitimate: {len(legitimate_pool)} / {TARGET_PER_CLASS}")
    print(f"Total:      {len(all_chunks)} amostras")
    print("="*40 + "\n")

    if len(all_chunks) < TOTAL_TARGET:
        print(f"⚠️ Aviso: Não foram encontradas amostras suficientes para atingir {TOTAL_TARGET}.")

    # Processamento de Embeddings e FAISS
    texts = [c["text"] for c in all_chunks]
    all_embeddings = []
    
    for i in range(0, len(texts), BATCH_SIZE):
        print(f"Vetorizando lote {i//BATCH_SIZE + 1}...")
        all_embeddings.append(embed(texts[i:i + BATCH_SIZE]))
    
    embeddings = np.vstack(all_embeddings).astype("float32")

    # Persistência
    index = faiss.IndexFlatL2(embeddings.shape[1])
    index.add(embeddings)
    
    with open(VECTORSTORE_DIR / "chunks.json", "w", encoding="utf-8") as f:
        json.dump(all_chunks, f, ensure_ascii=False, indent=2)
    faiss.write_index(index, str(VECTORSTORE_DIR / "index.faiss"))
    
    print(f"✅ Sucesso: Novo VectorStore equilibrado e salvo.")

if __name__ == "__main__":
    ingest_strictly_balanced()