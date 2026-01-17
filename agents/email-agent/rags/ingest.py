from pathlib import Path
import pickle
import numpy as np
import faiss

from rags.embeddings import embed_text

BASE_DIR = Path(__file__).parent
DOCS_PATH = BASE_DIR / "docs"
VECTORSTORE_PATH = BASE_DIR / "vectorstore"

VECTORSTORE_PATH.mkdir(parents=True, exist_ok=True)


def load_documents():
    documents = []
    for doc_file in DOCS_PATH.glob("*"):
        if doc_file.suffix.lower() in [".txt"]:
            with open(doc_file, "r", encoding="utf-8", errors="ignore") as f:
                documents.append(f.read())
    return documents


def split_documents(documents, chunk_size=500, overlap=100):
    chunks = []
    for doc in documents:
        start = 0
        while start < len(doc):
            end = min(start + chunk_size, len(doc))
            chunks.append(doc[start:end])
            start += chunk_size - overlap
    return chunks


def build_faiss_index(chunks):
    embeddings = embed(chunks)
    dimension = embeddings.shape[1]

    index = faiss.IndexFlatL2(dimension)
    index.add(embeddings.astype("float32"))

    return index


def ingest_and_index():
    documents = load_documents()
    if not documents:
        raise RuntimeError("Nenhum documento encontrado em rags/docs")

    chunks = split_documents(documents)

    index = build_faiss_index(chunks)

    # Persistência
    with open(VECTORSTORE_PATH / "chunks.pkl", "wb") as f:
        pickle.dump(chunks, f)

    faiss.write_index(index, str(VECTORSTORE_PATH / "index.faiss"))

    print(f"Ingest concluído: {len(chunks)} chunks indexados.")


if __name__ == "__main__":
    ingest_and_index()
