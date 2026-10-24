# Pipeline Contextual — Análise de Log por Fases Comportamentais

> Plano de implementação para um segundo pipeline de análise de logs, separado do pipeline linha-a-linha existente. Ainda não implementado — este documento serve de referência para a implementação futura.

## Contexto

O pipeline atual (`pipeline/`) traduz e busca ameaças **linha a linha**: cada linha de log vira uma descrição comportamental isolada, e a busca no Qdrant é híbrida (semântica + lexical por keyword). Isso já resolve "descrever o que o log faz", mas não captura a continuidade de um ataque ao longo do arquivo, e ainda depende de casamento lexical direto (`buscar_por_keywords`), que é "pegar pelo log de evento" em vez de raciocinar por contexto.

O objetivo é um **segundo pipeline, totalmente separado**, que:
1. Analisa o arquivo de log **como um todo**, não linha a linha.
2. Gera uma descrição comportamental dividida em **fases ordenadas** (ex: reconhecimento → login suspeito → persistência), capturando a sequência do ataque sem precisar de um agente de correlação à parte.
3. Busca ameaças no Qdrant **puramente por contexto/descrição semântica**, nunca por keyword/comando.
4. Convive com o pipeline atual — expõe um **novo endpoint** no mesmo `main.py`, sem alterar `/analyze` nem os agentes existentes.

Decisões já validadas: granularidade por **fases comportamentais ordenadas** (não uma única descrição global do arquivo) e integração via **novo endpoint no FastAPI atual** (não um serviço separado).

## Estrutura de arquivos novos

```
agents/log-agent/
├── pipeline_contextual/                  # pacote novo, irmão de pipeline/ — deixa claro que é independente
│   ├── __init__.py
│   ├── agente_resumidor_arquivo.py       # Stage 1 (map): chunk de linhas -> ResumoChunk
│   ├── agente_organizador_fases.py       # Stage 2 (reduce): ResumoChunk[] -> FaseComportamental[] ordenadas
│   ├── agente_comparador_contextual.py   # Stage 3: busca semântica pura por fase + síntese narrativa
│   └── gerador_relatorio_contextual.py   # Stage 4: PDF a partir de RelatorioContextual
├── services/
│   └── groq_client.py                    # NOVO helper: extrai _chamar_groq/_parse_retry_after (hoje duplicado
│                                          # em agente_tradutor_logs.py, agent_comparador_ameacas.py e
│                                          # builder/data_set_builder.py). Os 2 agentes novos usam este helper
│                                          # desde o início — evita criar uma 4ª/5ª cópia da mesma lógica de
│                                          # retry/backoff/429. Os arquivos antigos NÃO são tocados agora.
└── main.py                               # adiciona POST /analyze-contextual (não remove/altera nada existente)
```

Reaproveitamentos diretos do pipeline atual (import, sem modificar):
- `pipeline.agente_filtrador_logs.AgenteFiltadorLogs` — mesmo Stage 0 de pré-filtragem/detecção de plataforma.
- `retriever.semantic_retriever.RetrieverSemantico.buscar()` — já é 100% semântico (ignora `palavras_chave_filtro`); o pipeline contextual chama **só este método**, nunca `buscar_hibrido`/`buscar_por_keywords`.
- `services.qdrant_config` — mesma coleção `colecao_logs_patterns` (o payload já indexa `descricao_semantica_log`/`texto_busca_vetorial`; não precisa de nova coleção nem reingestão).
- O dict `_PLATAFORMA_MITRE_MAP` de `pipeline/agent_comparador_ameacas.py` é importado (não duplicado) para filtrar plataformas incompatíveis por fase, igual ao comparador antigo faz por linha.

## Dataclasses novas

**`agente_resumidor_arquivo.py`**
```python
@dataclass
class ResumoChunk:
    numero_chunk: int
    linha_inicio: int
    linha_fim: int
    resumo_comportamental: str
    entidades_identificadas: list[str]
    severidade_maxima: str = "info"
```

**`agente_organizador_fases.py`**
```python
@dataclass
class FaseComportamental:
    numero_fase: int
    linha_inicio: int
    linha_fim: int
    titulo_fase: str
    descricao_comportamental: str          # usado como query na busca semântica
    entidades_identificadas: list[str] = field(default_factory=list)
    severidade_inferida: str = "info"
    chunks_origem: list[int] = field(default_factory=list)
```

**`agente_comparador_contextual.py`** (espelha `AmeacaDetectada`/`RelatorioAmeacas` para reaproveitar padrão do gerador de PDF, trocando "evidência por linha" por "evidência por fase"):
```python
@dataclass
class EvidenciaFase:
    numero_fase: int
    linha_inicio: int
    linha_fim: int
    descricao_comportamental: str
    score_similaridade: float

@dataclass
class AmeacaContextual:
    tecnica_id: str
    nome_tecnica: str
    tatica: str
    tatica_id: str
    severidade: str
    confianca_media: float
    descricao_mitre: str
    descricao_semantica_log: str
    plataformas_mitre: list[str]
    fases_relacionadas: list[EvidenciaFase]
    analise_llm: str = ""
    recomendacoes: list[str] = field(default_factory=list)
    url_mitre: str = ""
    # score_risco: mesma fórmula/pesos de AmeacaDetectada.score_risco, usando len(fases_relacionadas)

@dataclass
class RelatorioContextual:
    arquivo_log: str
    total_linhas_analisadas: int
    total_fases: int
    fases: list[FaseComportamental]
    ameacas: list[AmeacaContextual]
    narrativa_incidente: str = ""     # conta a sequência do ataque, ponta a ponta
    resumo_executivo: str = ""
    severidade_geral: str = "low"
    timestamp_geracao: str = ""
```

## Estratégia de chunking + map-reduce

**Map** (`AgenteResumidorArquivo.resumir_arquivo`): divide as linhas relevantes (após Stage 0) em janelas de `CONTEXTUAL_CHUNK_SIZE` linhas (padrão 80 — bem maior que `TRADUTOR_BATCH_SIZE=15`, pois aqui queremos contexto amplo por chamada). Uma chamada LLM por chunk → `ResumoChunk`.

**Reduce** (`AgenteOrganizadorFases.organizar`), hierárquico para suportar arquivos grandes:
- Se `len(resumos) <= CONTEXTUAL_REDUCE_BATCH_SIZE` (padrão 20): uma única chamada LLM consolida tudo em `FaseComportamental[]` ordenadas.
- Se exceder: particiona em lotes de `CONTEXTUAL_REDUCE_BATCH_SIZE`, gera sub-fases por lote, e repete o reduce sobre as sub-fases resultantes até caber numa chamada final (`while len(items) > CONTEXTUAL_REDUCE_BATCH_SIZE: items = _reduzir_em_lotes(items)`).
- Trava de segurança: `linha_inicio`/`linha_fim` de cada fase são **recalculados no código** (min/max das linhas dos `chunks_origem`), nunca aceitos como o LLM os retornou — evita alucinação de números de linha. `numero_fase` é renumerado sequencialmente por `linha_inicio` ao final.

## Prompts LLM

Mesmo padrão dos agentes atuais (`response_format: json_object`, strip de blocos ```` ```json ````):

1. **Resumo de chunk** — pede `resumo_comportamental` (2-4 frases), `entidades_identificadas`, `severidade_maxima` para o trecho de linhas.
2. **Consolidação em fases** — recebe a lista ordenada de resumos (ou sub-fases), pede para agrupar em fases distintas quando o comportamento muda, retornando `titulo_fase`, `descricao_comportamental`, `entidades_identificadas`, `severidade_inferida`, `chunks_origem` (apenas os números fornecidos, sem inventar linhas).
3. **Síntese da narrativa do incidente** — recebe fases + técnicas MITRE associadas a cada uma, pede `narrativa_incidente` (6-10 frases contando a sequência), `resumo_executivo`, `severidade_geral`. Reaproveita a estrutura de `_gerar_resumo_executivo` do comparador atual.
4. **Análise por ameaça** — reaproveita literalmente o prompt de `_gerar_analise_ameaca`, só trocando "evidências por linha" por "fases relacionadas" no texto montado.

## Busca semântica pura por fase

`AgenteComparadorContextual` chama `RetrieverSemantico.buscar(query=fase.descricao_comportamental, top_k=CONTEXTUAL_TOP_K, limiar_score=CONTEXTUAL_SCORE_THRESHOLD)` — nunca lexical. Novas env vars com defaults próprios (thresholds do pipeline antigo foram calibrados para busca híbrida por linha, não se aplicam aqui):
- `CONTEXTUAL_TOP_K=5` (mais alto que `COMPARADOR_TOP_K`, pois uma fase pode mapear para várias técnicas relacionadas)
- `CONTEXTUAL_SCORE_THRESHOLD=0.45` (mais baixo que `COMPARADOR_SCORE_THRESHOLD=0.8`, pois sem o boost lexical artificial o score vetorial puro de textos longos tende a ser menor — ajustar empiricamente na verificação manual)

Agrupamento por `tecnica_id` e dedup por `numero_fase`, igual ao padrão do comparador atual.

## Novo endpoint em `main.py`

```python
POST /analyze-contextual
  file: UploadFile
  chunk_size: int = 80
  reduce_batch_size: int = 20
  top_k_busca: int = 5
  limiar_score: float = 0.45
  gerar_analise_llm: bool = True
```
Reaproveita `_validar_arquivo`, o padrão de upload em `UPLOAD_DIR`, `try/finally` de limpeza, e `background_tasks` para expirar PDFs/JSON — mesmo esqueleto de `analyze_file`, só chamando um novo `_processar_arquivo_contextual()` no lugar de `_processar_arquivo_logs()`. Reaproveita o mesmo `ProcessingResponse` (campos já servem). Atualiza a lista de endpoints em `GET /` para incluir a nova rota, sem tocar nas existentes.

## Novas variáveis `.env`

```
# =========== Pipeline Contextual (análise por fases) ===========
CONTEXTUAL_CHUNK_SIZE=80
CONTEXTUAL_REDUCE_BATCH_SIZE=20
CONTEXTUAL_TOP_K=5
CONTEXTUAL_SCORE_THRESHOLD=0.45
```

## Verificação

1. Criar um log sintético multi-fase de teste (reconhecimento/portscan → login SSH suspeito → cron job de persistência → exfiltração via curl/scp), cada fase com ~30-50 linhas.
2. Subir `uvicorn main:app --reload --port 8080` e chamar:
   ```bash
   curl -X POST http://localhost:8080/analyze-contextual \
     -F "file=@teste_contextual.log" -F "chunk_size=20" \
     -F "top_k_busca=5" -F "limiar_score=0.4" -F "gerar_analise_llm=true"
   ```
3. Conferir no JSON/PDF gerado:
   - `total_fases` bate com o número de comportamentos plantados.
   - `linha_inicio`/`linha_fim` das fases são crescentes e não se sobrepõem (confirma que o recálculo por código funcionou, não a alucinação do LLM).
   - Cada `AmeacaContextual.fases_relacionadas` aponta para a fase esperada (ex: T1046 na fase de recon).
   - `narrativa_incidente` conta a sequência na ordem certa.
4. Repetir com um arquivo grande (>2000 linhas, replicando o log de teste) e `CONTEXTUAL_REDUCE_BATCH_SIZE` baixo para forçar reduce hierárquico — confirmar que `total_fases` não explode e a ordem cronológica se mantém.
5. Rodar um teste de regressão no `/analyze` existente para confirmar que os novos imports/endpoint não quebraram o pipeline antigo.

## Arquivos críticos
- `agents/log-agent/main.py`
- `agents/log-agent/retriever/semantic_retriever.py` (reuso, sem alteração)
- `agents/log-agent/pipeline/agent_comparador_ameacas.py` (reuso do `_PLATAFORMA_MITRE_MAP`, sem alteração)
- `agents/log-agent/pipeline/agente_filtrador_logs.py` (reuso como Stage 0, sem alteração)
- `agents/log-agent/pipeline/gerador_relatorio.py` (referência de estilo para o novo gerador)
- `agents/log-agent/.env`
