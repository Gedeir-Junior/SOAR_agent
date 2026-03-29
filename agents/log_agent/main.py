from fastapi import FastAPI, UploadFile, File
import torch
import numpy as np
from services.qdrant_client import QdrantLogConnector
from services.reporter import SOCReporter
from utils.processor import LogProcessor
from core.embedder import LogEmbedder
from core.model import LSTMAutoencoder, calculate_anomaly_score

app = FastAPI(title="SOAR Log Agent v2")

# --- INICIALIZAÇÃO ---
processor = LogProcessor()
embedder = LogEmbedder()
qdrant = QdrantLogConnector()
reporter = SOCReporter(qdrant)

# Configurações do Modelo
INPUT_DIM = 384 
HIDDEN_DIM = 64
SEQ_LEN = 10
THRESHOLD = 0.18 # Ajuste conforme o treino

model = LSTMAutoencoder(INPUT_DIM, HIDDEN_DIM, SEQ_LEN)
# model.load_state_dict(torch.load("models/log_model.pth"))
model.eval()

@app.post("/analyze-logs")
async def analyze_logs(file: UploadFile = File(...)):
    content = await file.read()
    logs = content.decode("utf-8").splitlines()
    
    anomalies = []
    buffer = []

    for line in logs:
        # 1. Processamento
        cleaned_text, metadata = processor.process(line)
        vector = embedder.get_embedding(cleaned_text)
        buffer.append(vector)

        # 2. Análise de Sequência (Windowing)
        if len(buffer) == SEQ_LEN:
            input_seq = torch.FloatTensor(np.array([buffer]))
            
            with torch.no_grad():
                reconstructed = model(input_seq)
                score = calculate_anomaly_score(input_seq, reconstructed)

            # 3. Detecção e Geração de Report
            if score > THRESHOLD:
                # Salva no Qdrant para memória de longo prazo
                qdrant_id = qdrant.save_anomaly(vector, line, metadata)
                
                # O Reporter gera o contexto RAG para este incidente específico
                report_context = reporter.generate_incident_report(vector, line)
                
                anomalies.append({
                    "timestamp_detected": metadata.get("timestamp", "N/A"),
                    "threat_level": "CRITICAL" if metadata.get("is_root") else "MEDIUM",
                    "evidence": line,
                    "anomaly_score": round(score, 4),
                    "ai_analysis_report": report_context,
                    "qdrant_ref": qdrant_id
                })
            
            buffer.pop(0)

    # 4. Resumo Final para o Manager do SOAR
    return {
        "status": "Success",
        "file_analyzed": file.filename,
        "summary": {
            "total_lines": len(logs),
            "anomalies_count": len(anomalies),
            "threat_detected": len(anomalies) > 0
        },
        "incidents": anomalies
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)