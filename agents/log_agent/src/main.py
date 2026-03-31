from fastapi import FastAPI, UploadFile, File
from src.utils.processor import LogProcessor
from src.core.embedder import LogEmbedder
from src.services.qdrant_client import QdrantManager
from src.services.reporter import SOCReporter
import numpy as np

app = FastAPI()

# Inicializando componentes
processor = LogProcessor()
embedder = LogEmbedder()
qdrant = QdrantManager()
reporter = SOCReporter()

@app.post("/analyze")
async def analyze_logs(file: UploadFile = File(...)):
    content = await file.read()
    lines = content.decode("utf-8").splitlines()
    
    findings = []
    
    for line in lines:
        cleaned, metadata = processor.process(line)
        vector = embedder.get_vector(cleaned)
        
        # 1. Busca no MITRE (Qdrant)
        threat = qdrant.search_threat(vector)
        
        if threat:
            findings.append({
                "mitre_name": threat['name'],
                "mitre_id": threat['id'],
                "raw_log": line,
                "suggestion": threat['mitigation']
            })
            
    # 2. Geração do PDF se houver ameaças
    pdf_path = None
    if findings:
        pdf_path = reporter.generate_pdf(findings, file.filename)

    return {
        "filename": file.filename,
        "threats_found": len(findings),
        "report_generated": pdf_path if pdf_path else "No threats detected"
    }