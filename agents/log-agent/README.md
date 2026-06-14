# Log Agent - Pipeline de Análise de Logs com Detecção de Ameaças

## Visão Geral

O **Log Agent** é um pipeline automatizado de análise de logs que utiliza IA e o framework MITRE ATT&CK para detectar ameaças de segurança em tempo real. O pipeline integra três agentes principais:

```
┌─────────────────────────────────────────────────────────────────┐
│                     ARQUIVO DE LOG                              │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  AGENTE 1: TRADUTOR DE LOGS (AgenteTradutorLogs)                │
│  • Processa logs em lotes                                        │
│  • Chama Groq LLM para tradução comportamental                   │
│  • Extrai keywords e inferem severidade                          │
│  Output: list[LogTraduzido]                                      │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  AGENTE 2: COMPARADOR DE AMEAÇAS (AgenteComparadorAmeacas)      │
│  • Busca semântica e lexical no Qdrant                           │
│  • Busca híbrida: semantica + lexical (keywords)                │
│  • Consolida evidências por técnica MITRE                       │
│  • Gera análise LLM e recomendações                             │
│  Output: RelatorioAmeacas                                        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  AGENTE 3: GERADOR DE RELATÓRIO (gerar_pdf)                     │
│  • Gera PDF profissional com visualizações                      │
│  • Exporta relatório em JSON                                    │
│  Output: PDF + JSON                                              │
└─────────────────────────────────────────────────────────────────┘
```

## Arquitetura

### Estrutura de Pastas

```
log-agent/
├── main.py                          # Endpoint FastAPI principal
├── requirements.txt                 # Dependências
├── .env.example                     # Exemplo de configuração
├── app/
│   ├── __init__.py
│   ├── main.py                      # (não está sendo usado no novo pipeline)
│   └── ...
├── builder/
├── datasets/                        # Datasets MITRE ATT&CK
│   ├── enterprise-attack.json
│   ├── discovery.json
│   ├── execution.json
│   ├── initial_access.json
│   ├── privilege_escalation.json
│   ├── reconnaissance.json
│   └── stealth.json
├── ingestion/
├── pipeline/                        # CORE PIPELINE
│   ├── agente_tradutor_logs.py     # Agente 1: Tradução
│   ├── agent_comparador_ameacas.py # Agente 2: Comparação
│   └── gerador_relatorio.py        # Agente 3: Geração de Relatório
├── retriever/
│   ├── semantic_retriever.py       # Buscas no Qdrant
│   └── ...
└── services/
    ├── qdrant_config.py            # Configuração do Qdrant
    └── ollama_client.py
```

## Instalação e Configuração

### 1. Instalar Dependências

```bash
cd agents/log-agent
pip install -r requirements.txt
```

### 2. Configurar Variáveis de Ambiente

```bash
# Copiar arquivo de exemplo
cp .env.example .env

# Editar com suas configurações
vim .env
```

**Variáveis obrigatórias:**
- `GROQ_API_KEY`: Chave da API Groq para LLM
- `QDRANT_URL`: URL do servidor Qdrant (ex: http://localhost:6333)

### 3. Verificar Conexão com Qdrant

```bash
# Iniciar Qdrant (se usando Docker)
cd infra/
podman-compose up -d qdrant

# Verificar coleção
python -c "from services.qdrant_config import obter_cliente_qdrant; \
           client = obter_cliente_qdrant(); \
           print(client.get_collections())"
```

## Uso

### Como Endpoint FastAPI

```bash
# Iniciar servidor
uvicorn main:app --reload --host 0.0.0.0 --port 8080

# Ou usando Python diretamente
python main.py
```

**Endpoints disponíveis:**

#### Health Check
```bash
curl http://localhost:8080/health
```

#### Analisar Arquivo

```bash
curl -X POST http://localhost:8080/analyze \
  -F "file=@path/to/logfile.log"
```

**Resposta:**
```json
{
  "status": "success",
  "arquivo_log": "logfile.log",
  "timestamp": "2024-06-07T10:30:00",
  "total_linhas_analisadas": 245,
  "total_ameacas_detectadas": 7,
  "pdf_path": "logfile_20240607_103000_relatorio.pdf",
  "json_path": "logfile_20240607_103000_relatorio.json",
  "message": "Processamento concluído: 7 ameaça(s) detectada(s)"
}
```

#### Analisar Texto

```bash
curl -X POST http://localhost:8080/analyze-text \
  -H "Content-Type: application/json" \
  -d '{"logs": "2024-06-07 10:30:45 sshd: Invalid user admin from 192.168.1.100"}'
```

#### Listar Relatórios

```bash
curl http://localhost:8080/reports
```

#### Baixar Relatório

```bash
curl http://localhost:8080/reports/logfile_20240607_103000_relatorio.pdf -o relatorio.pdf
```

#### Documentação Interativa (Swagger)

```
http://localhost:8080/docs
```

### Uso Programático

```python
from pathlib import Path
from pipeline.agente_tradutor_logs import AgenteTradutorLogs
from pipeline.agent_comparador_ameacas import AgenteComparadorAmeacas
from pipeline.gerador_relatorio import gerar_pdf

# Stage 1: Tradução
tradutor = AgenteTradutorLogs(batch_size=15, ignorar_info=False)
traducoes = tradutor.traduzir_arquivo(Path("application.log"))

# Stage 2: Comparação
comparador = AgenteComparadorAmeacas(top_k=3, limiar_score=0.40)
relatorio = comparador.analisar(traducoes, nome_arquivo_log="application.log")

# Stage 3: Geração PDF
pdf_path = gerar_pdf(relatorio, Path("relatorio.pdf"))
print(f"Relatório gerado: {pdf_path}")
```

## Configuração de Pipeline

Via endpoint FastAPI, você pode passar configurações customizadas:

```json
{
  "batch_size": 15,
  "top_k_busca": 3,
  "limiar_score": 0.40,
  "gerar_analise_llm": true,
  "ignorar_info_logs": false
}
```

### Parâmetros

| Parâmetro | Tipo | Padrão | Descrição |
|-----------|------|--------|-----------|
| `batch_size` | int | 15 | Linhas de log por chamada ao LLM (maior = mais contexto, mais tokens) |
| `top_k_busca` | int | 3 | Resultados por busca semântica (maior = mais resultados, mais tempo) |
| `limiar_score` | float | 0.40 | Score mínimo de similaridade para consideração (0-1) |
| `gerar_analise_llm` | bool | true | Chamar LLM para análise de ameaças (consome tokens) |
| `ignorar_info_logs` | bool | false | Ignorar linhas classificadas como "info" |

## Estrutura de Dados

### LogTraduzido
```python
@dataclass
class LogTraduzido:
    linha_original: str                      # Linha bruta do log
    numero_linha: int                        # Número da linha
    descricao_comportamental: str            # Descrição semantica em PT
    keywords_extraidas: list[str]            # Keywords para busca lexical
    fonte_inferida: str                      # linux_syslog | windows_eventlog | ...
    severidade_inferida: str                 # info | low | medium | high | critical
```

### AmeacaDetectada
```python
@dataclass
class AmeacaDetectada:
    tecnica_id: str                          # Ex: T1566.002
    nome_tecnica: str                        # Ex: "Phishing: Spearphishing Link"
    tatica: str                              # Ex: "Initial Access"
    tatica_id: str                           # Ex: TA0001
    severidade: str                          # info | low | medium | high | critical
    confianca_media: float                   # 0-1
    descricao_mitre: str                     # Descrição oficial MITRE
    descricao_semantica_log: str             # Como aparece em logs
    plataformas_mitre: list[str]             # Windows, Linux, macOS, etc
    evidencias: list[EvidenciaLog]           # Linhas de log que suportam
    analise_llm: str                         # Análise gerada por IA
    recomendacoes: list[str]                 # Ações de resposta recomendadas
    url_mitre: str                           # Link para documentação MITRE
    
    @property
    def score_risco(self) -> float:          # Score composto de risco
```

### RelatorioAmeacas
```python
@dataclass
class RelatorioAmeacas:
    arquivo_log: str                         # Nome do arquivo analisado
    total_linhas_analisadas: int             # Linhas processadas
    total_ameacas_detectadas: int            # Ameaças únicas encontradas
    ameacas: list[AmeacaDetectada]           # Lista de ameaças
    resumo_executivo: str                    # Sumário em PT para executivos
    severidade_geral: str                    # Severidade geral do relatório
    timestamp_geracao: str                   # ISO 8601 timestamp
```

## Solução de Problemas

### 1. "GROQ_API_KEY não definida"

```bash
# Verificar se .env está carregado
cat .env | grep GROQ_API_KEY

# Ou defininir como variável de ambiente
export GROQ_API_KEY=gsk_xxx_your_key_here_xxx
```

### 2. "Erro ao conectar no servidor Qdrant"

```bash
# Verificar se Qdrant está rodando
curl http://localhost:6333/health

# Iniciar Qdrant
cd infra/
podman-compose up -d qdrant
docker logs qdrant
```

### 3. "JSON inválido na resposta do Groq"

- Verificar limite de rate limiting do Groq
- Reduzir `batch_size` para lotes menores
- Aumentar `LLM_RETRIES` no .env

### 4. "Nenhuma técnica encontrada acima do limiar"

- Reduzir `COMPARADOR_SCORE_THRESHOLD` no .env
- Aumentar `COMPARADOR_TOP_K`
- Verificar se coleção Qdrant tem dados

## Análise do Código

### Fluxo de Tradução (Agente 1)

1. Lê arquivo de logs
2. Divide em lotes de `batch_size` linhas
3. Para cada lote:
   - Constrói prompt com linhas bruas
   - Chama Groq LLM
   - Parseia resposta JSON
   - Extrai: descrição, keywords, severidade, fonte

### Fluxo de Comparação (Agente 2)

1. Para cada linha traduzida com severidade ≥ "low":
   - Faz busca híbrida no Qdrant:
     - Semântica: query de descrição comportamental
     - Lexical: keywords extraídas
   - Deduplica resultados por `tecnica_id`
   - Agrupa evidências por técnica
2. Para cada técnica encontrada:
   - Calcula score de confiança médio
   - Chama LLM para análise técnica (se habilitado)
   - Gera recomendações

### Fluxo de Geração (Agente 3)

1. Cria PDF com ReportLab:
   - Capa com severidade geral
   - Resumo executivo (LLM gerado)
   - Tabela de ameaças (ordenada por risco)
   - Detalhes por técnica com evidências
   - Rodapé com referências MITRE
2. Exporta relatório como JSON para arquivamento

## Performance

| Métrica | Valor | Notas |
|---------|-------|-------|
| Linhas por segundo | ~200 | Com batch_size=15, tempo de Groq |
| Arquivo 1000 linhas | ~2-3 min | Incluindo busca e PDF |
| Consumo LLM | ~50-100 tokens/linha | Com análise LLM habilitada |
| Pico de memória | ~1.2 GB | Carregamento de modelo embedding |

## Próximos Passos

- [ ] Integração com corretor de ameaças (correlação)
- [ ] Cache de embeddings para arquivos duplicate
- [ ] WebSocket para streaming de processamento
- [ ] Webhook callbacks para eventos
- [ ] Dashboard web de visualização
- [ ] Multi-tenancy com projetos

## Referências

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Groq API Documentation](https://console.groq.com/docs)
- [Qdrant Vector Database](https://qdrant.tech/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
