# Investigação e melhoria do pipeline contextual — sessão de 15/08/2026

## Arquitetura do log-agent

O `log-agent` é o serviço de análise de logs do SOAR_agent (FastAPI, `main.py`), com **dois pipelines de detecção em paralelo** que compartilham o mesmo Stage 0 e a mesma base de conhecimento MITRE, mas divergem depois disso:

**Pipeline linha-a-linha** (`pipeline/`, endpoint `POST /analyze`, o mais antigo):
1. `agente_filtrador_logs.py` — filtra ruído e detecta a plataforma predominante (linux/windows/macos/network).
2. `agente_tradutor_logs.py` — traduz/normaliza cada linha relevante.
3. `agent_comparador_ameacas.py` — compara **linha a linha** contra o banco vetorial (`_PLATAFORMA_MITRE_MAP` filtra técnicas incompatíveis com a plataforma detectada).
4. `gerador_relatorio.py` — gera o PDF final.

**Pipeline contextual** (`pipeline_contextual/`, endpoint `POST /analyze-contextual`, mais novo, implementado a partir de `PLANO_PIPELINE_CONTEXTUAL.md`):
1. Stage 0 — reaproveita o mesmo `AgenteFiltadorLogs`.
2. Stage 1 (map) — `agente_resumidor_arquivo.py`: divide as linhas em chunks (`CONTEXTUAL_CHUNK_SIZE`) e pede ao LLM um resumo comportamental por chunk, preservando artefatos literais (comandos, Event IDs, binários).
3. Stage 2 (reduce hierárquico) — `agente_organizador_fases.py`: consolida os resumos de chunk em fases comportamentais (ex.: Reconnaissance → Initial Access → Execution...), com uma fase residual de segurança para IDs que o LLM não referenciou em nenhuma fase.
4. Stage 3 — `agente_comparador_contextual.py`: busca semântica pura contra o Qdrant por fase (não linha a linha), gera a narrativa do incidente. Alterado nesta sessão para busca híbrida (resumo + texto bruto da fase) — ver linha do tempo abaixo.
5. Stage 4 — `gerador_relatorio_contextual.py`: PDF.

**Infraestrutura compartilhada pelos dois pipelines**:
- `services/groq_client.py` — chamadas ao Groq (chat completions) com parsing de retry-after e backoff exponencial em 429; usado por ambos os pipelines para todas as etapas que envolvem LLM.
- `services/qdrant_config.py` — cliente Qdrant e configuração da coleção `colecao_logs_patterns` (384 dimensões, distância cosseno).
- `retriever/semantic_retriever.py` (`RetrieverSemantico`) — encapsula o encoder `SentenceTransformer("all-MiniLM-L6-v2")` e a busca no Qdrant; expõe `buscar()` (semântica pura, usada em produção pelos dois pipelines), `buscar_por_keywords()` (lexical via `palavras_chave_filtro`, não usada em produção) e `buscar_hibrido()` (combina as duas, não usada em produção).
- **Base de conhecimento MITRE**: `builder/scheme.py` define o schema Pydantic (`ThreatDetectionPattern`); `datasets/*.json` guarda 15 táticas / 872 técnicas MITRE ATT&CK (geradas via subagentes Fable em 02–03/08); `ingestion/ingest_dataset.py` embeda e faz upsert no Qdrant — **819 dos 872 pontos** estão de fato indexados após o filtro de "evidência de log" aplicado nesta sessão (ver linha do tempo).
- **Harnesses de avaliação paralelos**: `ragas/` (avalia o pipeline linha-a-linha) e `ragas_contextual/` (avalia o pipeline contextual) — implementações caseiras estilo RAGAS (juiz LLM via Groq), não a lib oficial.

## Resumo executivo

Partindo da pergunta "que alterações no dataset melhorariam os resultados do teste de fase única" (baseline: recall médio de 28,3% em 22 cenários, com Initial Access em 0% sistemático), a investigação passou por três frentes — dataset, lógica de busca do pipeline e escolha do modelo LLM — e terminou identificando a causa raiz real: **o embedding `all-MiniLM-L6-v2` discrimina mal as ~819 técnicas MITRE do corpus** (scores concentrados entre 0,35 e 0,58), tornando o retriever sensível a variações pequenas de fraseio, independente de qual LLM gera o resumo ou de quão limpo está o dataset.

Duas correções reais e sem regressão foram aplicadas e mantidas: um filtro no dataset (técnicas que não geram evidência de log) e uma busca híbrida (resumo + texto bruto). Juntas levaram o recall médio de 28,3% para 36,1%. A troca de Groq por Claude foi testada nos 22 cenários e descartada — resultado estatisticamente empatado (35,0% vs 36,1%), com ganhos e perdas que se cancelam por tática.

## Linha do tempo cronológica

1. **Diagnóstico do dataset (achado #1 — contaminação por técnicas "sem evidência de log")**
   Cruzando os 22 resultados de teste de fase única com o conteúdo do dataset, identifiquei que técnicas de Reconnaissance/Resource Development (46 de 872, depois refinado para 53) tinham `descricao_semantica_log` admitindo explicitamente não gerar log ("nenhum log gerado", "fora da rede") — mas ainda competiam no índice vetorial, "engolindo" o ranking de consultas de Initial Access com vocabulário genérico de "ataque externo".

2. **Fix #1 aplicado — filtro de evidência observável**
   `ingestion/ingest_dataset.py`: nova função `_gera_evidencia_observavel()` exclui da ingestão qualquer técnica cuja descrição admita não deixar rastro em log. Reingestão: 872 → **819 pontos** no Qdrant (53 técnicas puladas).

3. **Teste do fix #1 — resultado parcial**
   A contaminação por Reconnaissance/Resource Development desapareceu (confirmado por reteste dos 4 cenários de Initial Access), mas o recall continuou em 0%. Causa raiz mais profunda encontrada: o resumo gerado pelo LLM (Groq) descreve a *mecânica de execução* do ataque, não o *vetor de acesso inicial* — a técnica certa existia no corpus (rank #30–#426 de 819), só não entrava no top-10 por causa da query, não do conteúdo indexado.

4. **Fix #2 aplicado — busca híbrida (resumo + texto bruto)**
   `pipeline_contextual/agente_comparador_contextual.py` e `ragas_contextual/pipeline_runner_contextual.py`: cada fase passou a ser buscada duas vezes — pelo resumo comportamental do LLM (como antes) e pelo texto bruto das linhas da fase (excluindo ruído já filtrado no Stage 0) — unindo os candidatos, mantendo o maior score por técnica. `main.py` atualizado para propagar `logs_filtrados` até o comparador.

5. **Suíte completa (22 cenários) com Groq — resultado: melhora real e sem regressão**
   Recall médio geral: **28,3% → 36,1%**. Initial Access saiu de 0% para 23,8%; Execution subiu de 16,1% para 28,6% (efeito colateral não previsto); Discovery e Stealth ficaram idênticos cenário a cenário (sem regressão).

6. **Matriz de confusão por tática — achado #2 (ruído de Persistence)**
   Construída cruzando os candidatos retornados com a tática real de cada `tecnica_id` no corpus. Achado novo: **Persistence é a maior fonte de ruído fora do alvo** em quase todas as táticas testadas (até 21 candidatos de Persistence vazando em cenários de Privilege Escalation) — mesmo em cenários com recall alto, a lista de candidatos vem parcialmente "suja".

7. **Piloto Claude (3 cenários) — metodologia sem vazamento de contexto**
   Preocupação levantada pelo usuário: um subagente com `fork` herdaria o gabarito já discutido na conversa. Solução: subagentes frescos (sem fork, contexto zero), recebendo apenas o prompt exato de produção do resumidor + o log bruto — nada de gabarito. Resultado: 2 de 3 cenários melhoraram (Initial Access 0%→33%, Execution 0%→17%), 1 empatou.

8. **Piloto Claude completo (22 cenários) — resultado: empate técnico**
   Recall médio geral: Groq 36,1% vs Claude 35,0% (Δ −1,1pp, dentro do ruído). Por tática, divergência forte: Initial Access **+19,6pp** a favor do Claude, mas Stealth **−16,7pp** (zerou onde o Groq acertava 67%) e Reconnaissance −11,7pp. Conclusão: não há vencedor consistente — cada modelo tem viés de linguagem diferente que casa melhor ou pior com o vocabulário de cada técnica MITRE.

9. **Investigação do caso `rede-stealth` (Groq 67% → Claude 0%)**
   Regenerei o resumo do Groq para o mesmo cenário e comparei rank a rank com o do Claude. Os dois resumos são igualmente detalhados e literais (124 vs 131 palavras, ambos citam os artefatos certos). A diferença veio de uma escolha de frase sutil (Groq: "exfiltração de dados via esteganografia"; Claude: "dump de credenciais via esteganografia") que empurrou o vetor do Claude para mais longe da descrição de T1027.003 no corpus. Mais revelador: **mesmo o resumo do Groq só coloca 1 das 3 técnicas esperadas dentro do top-10 de forma consistente** — o recall de 67% da rodada original dependeu de uma variação de fraseio entre chamadas (temperature=0,1) que hoje, reproduzida, não se repete exatamente. Conclusão: não é uma fraqueza do Claude, é evidência adicional de que o embedding discrimina mal nessa faixa de score (0,35–0,58), tornando qualquer resultado individual frágil a ruído de fraseio.

## O que isso significa

- **O dataset não era (só) o problema.** A hipótese inicial do usuário — "que mudanças no dataset melhorariam o resultado" — levou a uma correção real (filtro de evidência), mas o teto de melhoria por aí é baixo. O gargalo dominante está na camada de busca semântica, não no conteúdo do corpus.
- **A busca híbrida é a correção mais robusta encontrada nesta sessão** — melhora consistente, sem custo, sem regressão, não depende de qual LLM é usado. Deve ser considerada para produção.
- **Trocar Groq por Claude não se paga.** Mesmo usando o plano Pro (sem custo de API, via subagentes frescos), o ganho não é sistemático — melhora tanto quanto piora, dependendo da tática. Não há justificativa para pagar por chamadas de API para isso.
- **A causa raiz real e ainda não resolvida**: o embedding `all-MiniLM-L6-v2` comprime as descrições técnicas do MITR ATT&CK numa faixa de score estreita (~0,35–0,58), o que torna o top-10/threshold=0,45 uma linha de corte arbitrária — pequenas variações de fraseio (de qualquer origem: LLM, temperatura, dataset) decidem se uma técnica certa aparece ou não. Enquanto isso não for resolvido (reranking, embedding melhor, ou outra estratégia de busca), qualquer ajuste incremental (dataset, prompt, modelo) vai ter efeito limitado e instável entre execuções.
- **Bug secundário identificado, não corrigido**: o organizador de fases (`agente_organizador_fases.py`) corta a fronteira de fase de forma que pode excluir evidência relevante (caso concreto: linha de firmware comprometido excluída da fase de Initial Access em `windows-eventlog-initial-access`).

## Próximos passos possíveis (não implementados)

1. Reranking via LLM sobre um conjunto mais largo de candidatos (top-50/100), usando os trechos de log brutos da fase — ataca diretamente a fragilidade de corte por threshold identificada nos itens 3 e 9.
2. Investigar e corrigir o corte de fronteira de fase no organizador.
3. Avaliar um modelo de embedding diferente (maior, ou ajustado para o domínio de segurança) para aumentar a discriminação entre as ~819 técnicas.
4. Recalcular o cenário multi-fase original (`metricas_contextual.json`) com os fixes desta sessão — ainda não foi refeito.

## Arquivos salvos nesta sessão

- `ingestion/ingest_dataset.py` — filtro de evidência observável (não commitado).
- `pipeline_contextual/agente_comparador_contextual.py`, `ragas_contextual/pipeline_runner_contextual.py`, `main.py` — busca híbrida (não commitados).
- `ragas_contextual/resultados/resultado_suite_completa_groq_hibrido_2026-08-15.json` — 22 resultados detalhados da suíte Groq com busca híbrida (recall, acertos, candidatos por cenário).
- `ragas_contextual/resultados/matriz_confusao_hibrido_2026-08-15.json` e `.png` — matriz de confusão por tática.
- `ragas_contextual/resultados/piloto_claude_2026-08-15/` — 22 resumos gerados pelo Claude, `comparacao_completa_claude_vs_groq.json`, `comparacao_groq_vs_claude.png`.
- `ragas_contextual/resultados/RESUMO_INVESTIGACAO_2026-08-15.md` — este documento.

**Nota**: todo o pacote de trabalho (`pipeline_contextual/`, `ragas_contextual/`, `services/groq_client.py`, e os arquivos modificados) permanece **não commitado** no git, como já registrado em sessões anteriores — nenhum commit foi feito durante esta investigação.
