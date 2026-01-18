from pathlib import Path
import csv
import json
import faiss
import numpy as np

from rag.embeddings import embed

# Paths

BASE_DIR = Path(__file__).resolve().parent.parent

DATASETS_DIR = BASE_DIR / "datasets"
VECTORSTORE_DIR = BASE_DIR / "rag" / "vectorstore" / "examples"

VECTORSTORE_DIR.mkdir(parents=True, exist_ok=True)

TEXT_COLUMN = ["subject", "body", "text", "content", "message"]
LABEL_COLUMN = ["label", "class", "category", "spam"]

# Funções Auxiliares

def detect_column(columns, candidates):
    for candidate in candidates:
        if candidate in columns:
            return candidate
    return None

def ingest_csv():
    all_chunks = []

    for csv_file in DATASETS_DIR.glob("*.csv"):
        with open(csv_file, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            columns = reader.fieldnames or []

            text_col = detect_column(columns, TEXT_COLUMN)
            label_col = detect_column(columns, LABEL_COLUMN)

            if not text_col:
                print(f"No text column found in {csv_file.name}, skipping.")
                continue

            for row in reader:
                text = row.get(text_col, "").strip()
                if not text:
                    continue

                label = row.get(label_col, "unknown").strip() if label_col else "unknown"

                all_chunks.append({
                    "text": text,
                    "metadata": {"source": csv_file.name, "label": str(label).lower(), "type": "email_example"}
                })

    if not all_chunks:
        raise RuntimeError("Nenhum dado encontrado nos datasets CSV.")
    
    texts = [c["text"] for c in all_chunks]
    embeddings = embed(texts).astype("float32")

    index = faiss.IndexFlatL2(embeddings.shape[1])
    index.add(embeddings)

    with open(VECTORSTORE_DIR / "chunks.json", "w", encoding="utf-8") as f:
        json.dump(all_chunks, f, ensure_ascii=False, indent=2)

    faiss.write_index(index, str(VECTORSTORE_DIR / "index.faiss"))
    
    print(f"Ingest concluído: {len(all_chunks)} exemplos anexados.")

if __name__ == "__main__":
    ingest_csv()