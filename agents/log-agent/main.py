"""
log-agent/main.py

Endpoint FastAPI para o pipeline de análise de logs.

Pipeline:
  1. Recebe arquivo de log
  2. AgenteTradutorLogs: traduz para descrições comportamentais
  3. AgenteComparadorAmeacas: busca no Qdrant e detecta ameaças
  4. GeradorRelatorioPDF: gera relatório em PDF

Uso:
  uvicorn main:app --reload --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

import os
import sys
import json
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks, Form
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# =========================================================================
# Configuração de paths
# =========================================================================
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Importar agentes do pipeline
try:
    from pipeline.agente_filtrador_logs import AgenteFiltadorLogs
    from pipeline.agente_tradutor_logs import AgenteTradutorLogs
    from pipeline.agent_comparador_ameacas import AgenteComparadorAmeacas
    from pipeline.gerador_relatorio import gerar_pdf
except ImportError as e:
    print(f"[!] Erro ao importar agentes do pipeline: {e}")
    sys.exit(1)

# =========================================================================
# Configurações
# =========================================================================
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "reports"
UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

app = FastAPI(
    title="Log Analysis SOAR Agent",
    description="Pipeline de análise de logs com detecção de ameaças MITRE ATT&CK",
    version="1.0.0",
)

# Adicionar CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================================
# Modelos Pydantic
# =========================================================================
class ProcessingConfig(BaseModel):
    """Configurações do pipeline"""
    batch_size: int = 15
    top_k_busca: int = 3
    limiar_score: float = 0.7
    gerar_analise_llm: bool = True
    ignorar_info_logs: bool = False
    
    class Config:
        schema_extra = {
            "example": {
                "batch_size": 15,
                "top_k_busca": 3,
                "limiar_score": 0.7,
                "gerar_analise_llm": True,
                "ignorar_info_logs": False,
            }
        }


class ProcessingResponse(BaseModel):
    """Resposta do processamento"""
    status: str
    arquivo_log: str
    timestamp: str
    total_linhas_analisadas: int
    total_ameacas_detectadas: int
    pdf_path: Optional[str] = None
    json_path: Optional[str] = None
    message: str


class ErrorResponse(BaseModel):
    """Resposta de erro"""
    status: str = "error"
    message: str
    timestamp: str
    details: Optional[str] = None


# =========================================================================
# Funções auxiliares
# =========================================================================
def _validar_arquivo(arquivo: UploadFile) -> bool:
    """Valida se o arquivo é um arquivo de texto válido"""
    if not arquivo.filename:
        return False
    
    # Extensões permitidas
    extensoes_permitidas = {".log", ".txt", ".csv", ".json"}
    extensao = Path(arquivo.filename).suffix.lower()
    
    return extensao in extensoes_permitidas or arquivo.content_type in {
        "text/plain", "application/json", "text/csv"
    }


def _processar_arquivo_logs(
    arquivo_path: Path,
    config: ProcessingConfig,
) -> tuple[Path, Path, dict]:
    """
    Processa arquivo de logs através do pipeline completo.
    
    Retorna: (pdf_path, json_path, relatório_dict)
    """
    print(f"\n[*] Iniciando processamento: {arquivo_path.name}")
    print(f"[*] Configuração: batch_size={config.batch_size}, top_k={config.top_k_busca}, "
          f"limiar={config.limiar_score}")
    
    # --------- STAGE 0: Filtragem de Logs ---------
    print("\n[STAGE 0] Filtragem e detecção de plataforma…")
    try:
        filtrador = AgenteFiltadorLogs()
        logs_filtrados, plataforma_predominante = filtrador.filtrar_arquivo(arquivo_path)
        print(f"[✓] {len(logs_filtrados)} linhas analisadas")
        
        # Extrai tags únicas de todas as linhas
        todos_tags = set()
        for log in logs_filtrados:
            todos_tags.update(log.tags_plataforma)
        
        # Filtra linhas que NÃO foram removidas por serem inofensivas
        linhas_para_traduzir = [lf.numero_linha for lf in logs_filtrados if not lf.foi_filtrado]
        logs_removidos = len(logs_filtrados) - len(linhas_para_traduzir)
        print(f"[✓] {logs_removidos} linhas removidas (comandos inofensivos)")
        print(f"[✓] Plataforma detectada: {plataforma_predominante}, Tags: {', '.join(todos_tags)}")
        
    except Exception as e:
        print(f"[✗] Erro na filtragem: {e}")
        raise RuntimeError(f"Falha ao filtrar logs: {e}") from e
    
    # --------- STAGE 1: Tradução de Logs ---------
    print("\n[STAGE 1] Tradução de logs…")
    try:
        tradutor = AgenteTradutorLogs(
            batch_size=config.batch_size,
            ignorar_info=config.ignorar_info_logs,
        )
        # Passa os LogFiltrado do Stage 0 — logs inofensivos já excluídos,
        # números de linha originais preservados para o relatório final.
        traducoes = tradutor.traduzir_logs_filtrados(
            logs_filtrados=logs_filtrados,
            plataforma=plataforma_predominante,
            tags_plataforma=list(todos_tags),
        )
        print(f"[✓] {len(traducoes)} linhas traduzidas com sucesso")
    except Exception as e:
        print(f"[✗] Erro na tradução: {e}")
        raise RuntimeError(f"Falha ao traduzir arquivo: {e}") from e
    
    # --------- STAGE 2: Comparação de Ameaças ---------
    print("\n[STAGE 2] Comparação com banco de ameaças…")
    try:
        comparador = AgenteComparadorAmeacas(
            top_k=config.top_k_busca,
            limiar_score=config.limiar_score,
            gerar_analise_llm=config.gerar_analise_llm,
        )
        relatorio = comparador.analisar(
            traducoes=traducoes,
            nome_arquivo_log=arquivo_path.name,
        )
        print(f"[✓] {relatorio.total_ameacas_detectadas} ameaça(s) detectada(s)")
        print(f"[✓] Severidade geral: {relatorio.severidade_geral}")
    except Exception as e:
        print(f"[✗] Erro na comparação: {e}")
        raise RuntimeError(f"Falha ao comparar ameaças: {e}") from e
    
    # --------- STAGE 3: Geração de Relatório PDF ---------
    print("\n[STAGE 3] Geração de relatório PDF…")
    try:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        nome_base = arquivo_path.stem
        pdf_filename = f"{nome_base}_{timestamp}_relatorio.pdf"
        pdf_path = OUTPUT_DIR / pdf_filename
        
        pdf_gerado = gerar_pdf(relatorio, pdf_path)
        print(f"[✓] PDF gerado: {pdf_gerado.name}")
    except Exception as e:
        print(f"[✗] Erro na geração de PDF: {e}")
        # Continua mesmo se falhar o PDF para salvar JSON
        pdf_gerado = None
    
    # --------- STAGE 4: Exportação de Relatório JSON ---------
    print("\n[STAGE 4] Exportação de relatório JSON…")
    try:
        import dataclasses
        
        json_filename = f"{nome_base}_{timestamp}_relatorio.json"
        json_path = OUTPUT_DIR / json_filename
        
        # Serializa dataclasses para JSON
        def dataclass_serializer(obj):
            if dataclasses.is_dataclass(obj):
                return dataclasses.asdict(obj)
            raise TypeError(f"Tipo não serializável: {type(obj)}")
        
        relatorio_dict = {
            "arquivo_log": relatorio.arquivo_log,
            "timestamp_geracao": relatorio.timestamp_geracao,
            "total_linhas_analisadas": relatorio.total_linhas_analisadas,
            "total_ameacas_detectadas": relatorio.total_ameacas_detectadas,
            "severidade_geral": relatorio.severidade_geral,
            "resumo_executivo": relatorio.resumo_executivo,
            "ameacas": [dataclasses.asdict(a) for a in relatorio.ameacas],
        }
        
        with json_path.open("w", encoding="utf-8") as f:
            json.dump(relatorio_dict, f, indent=2, ensure_ascii=False, default=dataclass_serializer)
        
        print(f"[✓] JSON exportado: {json_path.name}")
    except Exception as e:
        print(f"[✗] Erro na exportação JSON: {e}")
        json_path = None
    
    print(f"\n[✓] Processamento concluído com sucesso!")
    print(f"    PDF: {pdf_gerado}")
    print(f"    JSON: {json_path}")
    
    return pdf_gerado, json_path, relatorio_dict


def _limpar_arquivo(path: Optional[Path], delay_segundos: int = 3600) -> None:
    """Limpa arquivo após um delay (em background task)"""
    if path and path.exists():
        import time
        time.sleep(delay_segundos)
        try:
            path.unlink()
            print(f"[*] Arquivo removido: {path.name}")
        except Exception as e:
            print(f"[!] Erro ao remover {path.name}: {e}")


# =========================================================================
# Endpoints
# =========================================================================

@app.get("/", tags=["Health"])
async def root():
    """Verifica se o agente está ativo"""
    return {
        "status": "ok",
        "agente": "log-agent",
        "version": "1.0.0",
        "endpoints": {
            "POST /analyze": "Analisa arquivo de logs",
            "POST /analyze-text": "Analisa texto de logs",
            "GET /docs": "Documentação interativa (Swagger)",
        }
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check detalhado"""
    checks = {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "upload_dir": str(UPLOAD_DIR),
        "output_dir": str(OUTPUT_DIR),
    }
    
    # Verifica conexão com Qdrant
    try:
        from services.qdrant_config import obter_cliente_qdrant
        client = obter_cliente_qdrant()
        collections = client.get_collections()
        checks["qdrant"] = "✓ conectado"
        checks["collections"] = len(collections.collections)
    except Exception as e:
        checks["qdrant"] = f"✗ erro: {str(e)[:50]}"
    
    return checks


@app.post("/analyze", tags=["Processing"], response_model=ProcessingResponse)
async def analyze_file(
    file: UploadFile = File(...),
    batch_size: int = Form(15),
    top_k_busca: int = Form(3),
    limiar_score: float = Form(0.40),
    gerar_analise_llm: bool = Form(True),
    ignorar_info_logs: bool = Form(False),
    background_tasks: BackgroundTasks = None,
):
    """
    Analisa um arquivo de logs através do pipeline completo.
    
    - **file**: arquivo de logs (.log, .txt, .csv, .json)
    - **batch_size**: linhas por lote ao LLM (padrão: 15)
    - **top_k_busca**: resultados por busca semântica (padrão: 3)
    - **limiar_score**: score mínimo 0-1 (padrão: 0.40)
    - **gerar_analise_llm**: gerar análise por IA (padrão: true)
    - **ignorar_info_logs**: ignorar linhas "info" (padrão: false)
    
    Retorna URLs para acessar o PDF e JSON gerados.
    """
    config = ProcessingConfig(
        batch_size=batch_size,
        top_k_busca=top_k_busca,
        limiar_score=limiar_score,
        gerar_analise_llm=gerar_analise_llm,
        ignorar_info_logs=ignorar_info_logs,
    )
    
    timestamp = datetime.now().isoformat()
    
    try:
        # Valida arquivo
        if not _validar_arquivo(file):
            raise HTTPException(
                status_code=400,
                detail=f"Arquivo inválido. Extensões permitidas: .log, .txt, .csv, .json"
            )
        
        # Salva arquivo temporário
        temp_path = UPLOAD_DIR / f"temp_{file.filename}"
        with temp_path.open("wb") as f:
            conteudo = await file.read()
            f.write(conteudo)
        
        # Processa arquivo
        try:
            pdf_path, json_path, relatorio_dict = _processar_arquivo_logs(temp_path, config)
        finally:
            # Limpa arquivo temporário
            if temp_path.exists():
                temp_path.unlink()
        
        # Agenda limpeza dos arquivos de saída após 1 hora
        if background_tasks and pdf_path:
            background_tasks.add_task(_limpar_arquivo, pdf_path)
        if background_tasks and json_path:
            background_tasks.add_task(_limpar_arquivo, json_path)
        
        return ProcessingResponse(
            status="success",
            arquivo_log=file.filename,
            timestamp=timestamp,
            total_linhas_analisadas=relatorio_dict.get("total_linhas_analisadas", 0),
            total_ameacas_detectadas=relatorio_dict.get("total_ameacas_detectadas", 0),
            pdf_path=str(pdf_path.name) if pdf_path else None,
            json_path=str(json_path.name) if json_path else None,
            message=f"Processamento concluído: {relatorio_dict.get('total_ameacas_detectadas', 0)} ameaça(s) detectada(s)",
        )
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


@app.post("/analyze-text", tags=["Processing"], response_model=ProcessingResponse)
async def analyze_text(
    logs: str = Form(...),
    batch_size: int = Form(15),
    top_k_busca: int = Form(3),
    limiar_score: float = Form(0.40),
    gerar_analise_llm: bool = Form(True),
    ignorar_info_logs: bool = Form(False),
):
    """
    Analisa texto de logs diretamente (sem arquivo).
    
    - **logs**: texto dos logs para analisar
    - **batch_size**: linhas por lote ao LLM (padrão: 15)
    - **top_k_busca**: resultados por busca semântica (padrão: 3)
    - **limiar_score**: score mínimo 0-1 (padrão: 0.40)
    - **gerar_analise_llm**: gerar análise por IA (padrão: true)
    - **ignorar_info_logs**: ignorar linhas "info" (padrão: false)
    """
    config = ProcessingConfig(
        batch_size=batch_size,
        top_k_busca=top_k_busca,
        limiar_score=limiar_score,
        gerar_analise_llm=gerar_analise_llm,
        ignorar_info_logs=ignorar_info_logs,
    )
    
    timestamp = datetime.now().isoformat()
    
    try:
        # Valida entrada
        if not logs or len(logs.strip()) == 0:
            raise HTTPException(
                status_code=400,
                detail="Texto de logs vazio"
            )
        
        # Cria arquivo temporário com o texto
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".log",
            dir=UPLOAD_DIR,
            delete=False,
            encoding="utf-8"
        ) as f:
            temp_path = Path(f.name)
            f.write(logs)
        
        try:
            pdf_path, json_path, relatorio_dict = _processar_arquivo_logs(temp_path, config)
        finally:
            if temp_path.exists():
                temp_path.unlink()
        
        return ProcessingResponse(
            status="success",
            arquivo_log="text_input",
            timestamp=timestamp,
            total_linhas_analisadas=relatorio_dict.get("total_linhas_analisadas", 0),
            total_ameacas_detectadas=relatorio_dict.get("total_ameacas_detectadas", 0),
            pdf_path=str(pdf_path.name) if pdf_path else None,
            json_path=str(json_path.name) if json_path else None,
            message=f"Processamento concluído: {relatorio_dict.get('total_ameacas_detectadas', 0)} ameaça(s) detectada(s)",
        )
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


@app.get("/reports/{filename}", tags=["Reports"])
async def download_report(filename: str):
    """
    Baixa um relatório gerado (PDF ou JSON).
    
    - **filename**: nome do arquivo gerado
    """
    file_path = OUTPUT_DIR / filename
    
    if not file_path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Arquivo não encontrado: {filename}"
        )
    
    # Valida que o arquivo está dentro do diretório permitido
    try:
        file_path.resolve().relative_to(OUTPUT_DIR.resolve())
    except ValueError:
        raise HTTPException(
            status_code=403,
            detail="Acesso negado"
        )
    
    media_type = "application/pdf" if filename.endswith(".pdf") else "application/json"
    return FileResponse(file_path, media_type=media_type, filename=filename)


@app.get("/reports", tags=["Reports"])
async def list_reports():
    """Lista todos os relatórios disponíveis"""
    try:
        arquivos = sorted(OUTPUT_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
        
        return {
            "status": "success",
            "total": len(arquivos),
            "arquivos": [
                {
                    "nome": f.name,
                    "tipo": f.suffix,
                    "tamanho_kb": round(f.stat().st_size / 1024, 2),
                    "criado": datetime.fromtimestamp(f.stat().st_mtime).isoformat(),
                }
                for f in arquivos[:50]  # Últimos 50
            ]
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erro ao listar relatórios: {str(e)}"
        )


# =========================================================================
# Exception Handlers
# =========================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "status": "error",
            "message": exc.detail,
            "timestamp": datetime.now().isoformat(),
        }
    )


# =========================================================================
# Main
# =========================================================================

if __name__ == "__main__":
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║        Log Analysis SOAR Agent - FastAPI Server              ║
    ║        Threat Detection with MITRE ATT&CK                    ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    port = int(os.getenv("LOG_AGENT_PORT", "8080"))
    host = os.getenv("LOG_AGENT_HOST", "0.0.0.0")
    
    print(f"[*] Iniciando servidor em http://{host}:{port}")
    print(f"[*] Documentação: http://{host}:{port}/docs")
    print(f"[*] Upload dir: {UPLOAD_DIR}")
    print(f"[*] Output dir: {OUTPUT_DIR}")
    
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level="info",
    )