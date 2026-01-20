from pathlib import Path
import numpy as np 
import json 
import fitz 
import faiss 

from rag.embeddings import embed

# PATHs e constants

BASE_DIR = Path(__file__).resolve().parent.parent.parent
GUIDES_DIR = BASE_DIR / "docs"
VECTORSTORE_DIR = BASE_DIR / "rag" / "vectorstore"/ "guides"

VECTORSTORE_DIR.mkdir(parents=True, exist_ok=True)

CHUNKS_PATH = VECTORSTORE_DIR / "chunks.json"
INDEX_PATH = VECTORSTORE_DIR / "index.faiss"

# Configurações de chunking
CHUNK_SIZE = 800
CHUNK_OVERLAP = 150

# Funções auxiliadoras

def extract_text_from_pdf(pdf_path: Path):
    """
    Extrai texto de um arquivo PDF
    """
    try:

        doc = fitz.open(pdf_path)
        pages = []

        for page_num, page in enumerate(doc, start=1):
            text = page.get_text()
            if text.strip():
                pages.append({
                    "text": text,
                    "page": page_num
                })
        return pages
    except Exception as e:
        print(f"Erro ao extrair texto de {pdf_path.name}: {e}")
        return []
    

def chunk_text(text: str, size: int, overlap: int):
    """ 
    Divide o texto em chunks com tamanho e overlap especificados
    """

    chunks = []
    start = 0

    step = size - overlap

    while start < len(text):
        end = start + size
        chunks.append(text[start:end])
        start += step
    
    return chunks

def ingest_pdfs():
    """
    Ingestão de guias em PDF, extração de texto, chunking, 
    vetorização e armazenamento no FAISS
    """

    all_chunks = []

    # Itera sobre todos os PDFs na pasta de guias
    for pdf_file in GUIDES_DIR.glob("*.pdf"):
        pages = extract_text_from_pdf(pdf_file)

        for page in pages:
            page_chunks = chunk_text(page["text"], CHUNK_SIZE, CHUNK_OVERLAP)

            for chunk in page_chunks:
                all_chunks.append({
                    "text": chunk,
                    "metadata": {
                        "source": pdf_file.name,
                        "page": page["page"],
                        "type": "pdf"
                    }
                })
    if not all_chunks:
        raise RuntimeError("Nenhum PDF válido encontrado em /docs")
    
    texts = [c["text"] for c in all_chunks]
    embeddings = embed(texts).astype("float32")

    index = faiss.IndexFlatL2(embeddings.shape[1])
    index.add(embeddings)

    with open(CHUNKS_PATH, "w", encoding="utf-8") as f:
        json.dump(all_chunks, f, ensure_ascii=False, indent=2)

    faiss.write_index(index, str(INDEX_PATH))
    
    print(f"Ingest concluído: {len(all_chunks)} chunks vetorizados.")

if __name__ == "__main__":
    ingest_pdfs()

