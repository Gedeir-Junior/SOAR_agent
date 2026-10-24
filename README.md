# SOAR Agent

Agentes de IA para automação de resposta a incidentes de segurança (SOAR), desenvolvidos como projeto de Iniciação Científica (EMC/UFG).

| Componente | Pasta | O que faz | Porta |
|---|---|---|---|
| **BERT Classifier** | `BERT_Classifier/` | Triagem rápida de phishing com BERT calibrado (Temperature Scaling + Monte Carlo Dropout) | 8002 |
| **Email Agent** | `agents/email-agent/` | Classificação de phishing com LLM (Mistral-7B via Ollama) + RAG sobre FAISS, para os casos em que o BERT fica em dúvida | 8001 |
| **Log Agent** | `agents/log-agent/` | Detecção de técnicas MITRE ATT&CK em logs (pipeline linha a linha e pipeline contextual por fases), com RAG sobre Qdrant + LLM via Groq | 8080 |
| **Manager** | `manager/` | Orquestrador de incidentes (**em desenvolvimento**: por enquanto só os schemas) | — |

Serviços de apoio: **Ollama** (11434), **Qdrant** (6333/6334) e **n8n** (5678).

---

## Pré-requisitos

- Python 3.11+
- Podman (ou Docker)
- Chave de API da [Groq](https://console.groq.com), usada pelo Log Agent
- ~8 GB de RAM livres para o Ollama com Mistral-7B

Crie a rede usada pelos containers (uma vez só):

```bash
podman network create soar_net
```

---

## 1. Serviços de apoio

### Qdrant (banco vetorial do Log Agent)

```bash
podman run -d --name qdrant_vector_db --network soar_net \
  -p 6333:6333 -p 6334:6334 \
  -v qdrant_data:/qdrant/storage:z \
  qdrant/qdrant:latest
```

Painel: http://localhost:6333/dashboard

### Ollama (LLM do Email Agent)

```bash
podman run -d --name ollama --network soar_net \
  -p 11434:11434 -v ollama_data:/root/.ollama \
  ollama/ollama:latest

podman exec -it ollama ollama pull mistral
```

### n8n (opcional, orquestração dos fluxos)

```bash
podman run -d --name n8n --network soar_net -p 5678:5678 \
  -e N8N_BASIC_AUTH_ACTIVE=true \
  -e N8N_BASIC_AUTH_USER=<usuario> \
  -e N8N_BASIC_AUTH_PASSWORD=<senha> \
  -e GENERIC_TIMEZONE=America/Sao_Paulo \
  -v n8n_data:/home/node/.n8n \
  n8nio/n8n:latest
```

> A pasta `infra/`, com o `podman-compose.yml` que sobe todos os serviços juntos, não é versionada. Se você tiver o arquivo localmente: `cd infra && podman-compose up -d`.

---

## 2. BERT Classifier (porta 8002)

O modelo treinado **não está no repositório** (`BERT_Classifier/models/` é ignorado pelo git). Coloque os arquivos do modelo (`config.json`, pesos, `tokenizer.json`, `vocab.txt` etc.) em `BERT_Classifier/models/bert-model-4/`.

```bash
cd BERT_Classifier
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8002
```

Teste:

```bash
curl http://localhost:8002/health

curl -X POST http://localhost:8002/classify -H "Content-Type: application/json" -d '{
  "sender": "suporte@banco-seguro.xyz",
  "subject": "Sua conta será bloqueada",
  "body": "Clique no link abaixo para confirmar seus dados em até 24h."
}'
```

A resposta traz `classification` (`phishing`, `legitimate` ou `uncertain`) e `action` (`auto_process` ou `delegate_to_llm`). Os e-mails com `delegate_to_llm` devem ser enviados ao Email Agent.

---

## 3. Email Agent (porta 8001)

### 3.1 Montar a base RAG (FAISS)

Os dados de entrada não são versionados. Antes de rodar, coloque:
- os CSVs de e-mails (ex.: CEAS_08, SpamAssassin) em `agents/email-agent/datasets/`
- os guias de identificação de phishing em PDF em `agents/email-agent/docs/`

```bash
cd agents/email-agent
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m rag.ingest.ingest_csv      # gera rag/vectorstore/examples/
python -m rag.ingest.ingest_guides   # gera rag/vectorstore/guides/
```

### 3.2 Subir a API

O agente chama o Ollama em `http://ollama:11434` (endereço fixo em `app/classifier.py`), então ele deve rodar **em container, na mesma rede do Ollama**:

```bash
podman build -t email-agent agents/email-agent
podman run -d --name email-agent --network soar_net -p 8001:8001 \
  -e PYTHONPATH=/app \
  email-agent uvicorn app.main:app --host 0.0.0.0 --port 8001
```

> Gere o vectorstore (3.1) **antes** do `podman build`, porque a pasta é copiada para dentro da imagem.

Teste:

```bash
curl -X POST http://localhost:8001/classify -H "Content-Type: application/json" -d '{
  "sender": "suporte@banco-seguro.xyz",
  "subject": "Sua conta será bloqueada",
  "body": "Clique no link abaixo para confirmar seus dados em até 24h.",
  "links": ["http://banco-seguro.xyz/login"]
}'
```

A análise leva de 1 a 5 minutos por e-mail em CPU.

---

## 4. Log Agent (porta 8080)

Todos os comandos desta seção são executados **de dentro de `agents/log-agent/`**.

### 4.1 Instalação e configuração

```bash
cd agents/log-agent
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Crie o arquivo `agents/log-agent/.env`. Ele é ignorado pelo git; **nunca commite sua chave**.

```ini
# LLM (Groq)
GROQ_API_KEY=gsk_sua_chave_aqui
GROQ_MODEL=llama-3.3-70b-versatile
LLM_RETRIES=3

# Pipeline linha a linha
TRADUTOR_BATCH_SIZE=15
COMPARADOR_TOP_K=1
COMPARADOR_SCORE_THRESHOLD=0.8

# Retriever / embeddings
EMBEDDING_MODEL=all-MiniLM-L6-v2
RETRIEVER_TOP_K=3
RETRIEVER_SCORE_THRESHOLD=0.8

# Pipeline contextual (por fases)
CONTEXTUAL_CHUNK_SIZE=20
CONTEXTUAL_REDUCE_BATCH_SIZE=20
CONTEXTUAL_TOP_K=10
CONTEXTUAL_SCORE_THRESHOLD=0.45

# Qdrant
QDRANT_URL=http://localhost:6333
QDRANT_COLLECTION=colecao_logs_patterns
QDRANT_VECTOR_DIMENSION=384

# Servidor
LOG_AGENT_HOST=0.0.0.0
LOG_AGENT_PORT=8080
LOG_LEVEL=INFO
```

### 4.2 Dataset MITRE ATT&CK e ingestão no Qdrant

O dataset (um JSON por tática em `agents/log-agent/datasets/`) **não é versionado**. Para gerá-lo a partir do bundle STIX oficial do MITRE ([`enterprise-attack.json`](https://github.com/mitre-attack/attack-stix-data)):

```bash
python builder/data_set_builder.py --stix-path enterprise-attack.json --list-tactics
python builder/data_set_builder.py --stix-path enterprise-attack.json --tactic "Initial Access"
# repita para cada tática; --resume continua de onde parou, --limit N limita para testes
```

Com os JSONs em `datasets/` e o Qdrant rodando:

```bash
python ingestion/ingest_dataset.py
```

As técnicas que não geram evidência em log (OSINT passivo, infraestrutura do atacante) são descartadas na ingestão. Com o dataset completo, a coleção fica com **819 pontos**.

### 4.3 Subir a API

```bash
python main.py
# ou, com recarga automática:
uvicorn main:app --host 0.0.0.0 --port 8080 --reload
```

Documentação interativa (Swagger): http://localhost:8080/docs

| Método | Rota | Descrição |
|---|---|---|
| GET | `/health` | Status do serviço e da conexão com o Qdrant |
| POST | `/analyze` | Pipeline linha a linha (upload de arquivo) |
| POST | `/analyze-text` | Pipeline linha a linha (texto no corpo) |
| POST | `/analyze-contextual` | Pipeline contextual por fases (upload de arquivo) |
| GET | `/reports` | Lista os relatórios PDF gerados |
| GET | `/reports/{filename}` | Baixa um relatório |

Exemplo:

```bash
curl -X POST http://localhost:8080/analyze-contextual \
  -F "file=@meu_arquivo.log" \
  -F "top_k_busca=10" -F "limiar_score=0.45"
```

### 4.4 Avaliação (estilo RAGAS)

**Pipeline linha a linha** (`ragas/`):

```bash
python ragas/gerador_logs_siteticos.py --json-dir datasets   # logs sintéticos + gabaritos
python ragas/construtor_dataset.py                           # roda o pipeline sobre eles
python ragas/avaliador.py                                    # precisão, recall, F1
```

**Pipeline contextual** (`ragas_contextual/`):

```bash
python ragas_contextual/gerador_logs_multifase.py --json-dir datasets   # logs multifase + gabaritos
python ragas_contextual/construtor_dataset_contextual.py --top-k 10      # roda o pipeline
python ragas_contextual/avaliador_contextual.py                          # context precision/recall, faithfulness, relevancy

# um único arquivo
python ragas_contextual/pipeline_runner_contextual.py ragas_contextual/resultados/rede-multifase.log --top-k 10
```

Os resultados ficam em `ragas/resultados/` e `ragas_contextual/resultados/`. Os arquivos `.log` sintéticos não são versionados (regra `*.log` do `.gitignore`); gere-os de novo com os comandos acima.

> **Rate limit da Groq:** o plano gratuito tem limites de tokens por minuto e por dia. Rodar a suíte inteira de uma vez com `llama-3.3-70b-versatile` gera muitos erros 429, então rode os cenários aos poucos.

Mais detalhes da arquitetura em [`agents/log-agent/README.md`](agents/log-agent/README.md) e [`agents/log-agent/PLANO_PIPELINE_CONTEXTUAL.md`](agents/log-agent/PLANO_PIPELINE_CONTEXTUAL.md).

---

## Solução de problemas

| Erro | Causa provável | Solução |
|---|---|---|
| `GROQ_API_KEY não definida no .env` | `.env` ausente, ou comando rodado fora de `agents/log-agent/` | Crie o `.env` (seção 4.1) e rode de dentro da pasta |
| `Erro ao conectar no servidor Qdrant` | Qdrant parado | `podman start qdrant_vector_db` |
| Groq retorna 429 | Limite de requisições ou de tokens | Aguarde alguns minutos ou use um modelo menor em `GROQ_MODEL` |
| Groq diz que o modelo não existe | Modelo descontinuado pela Groq | Atualize `GROQ_MODEL` (ex.: `llama-3.3-70b-versatile`) |
| Email Agent não encontra o Ollama | Agente rodando fora da rede `soar_net` | Rode o agente em container com `--network soar_net` |
| BERT não inicia | Modelo ausente | Coloque o modelo em `BERT_Classifier/models/bert-model-4/` |

## O que não é versionado

`.env`, `infra/`, `BERT_Classifier/models/`, `BERT_Classifier/Containerfile`, `agents/*/datasets/`, `agents/email-agent/docs/`, `agents/email-agent/rag/vectorstore/`, arquivos `*.log` e `Relatórios/`.
