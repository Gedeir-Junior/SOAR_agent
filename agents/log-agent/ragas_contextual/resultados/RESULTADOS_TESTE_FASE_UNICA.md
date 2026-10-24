# Resultados — Teste de Fase Única do Pipeline Contextual

**Data:** 06–07/08/2026

## Objetivo

Validar se o pipeline contextual (`pipeline_contextual/`) recupera corretamente as
técnicas MITRE ATT&CK de um log contendo **uma única tática/fase de ameaça**, sem o
ruído de organizar múltiplas fases no mesmo arquivo. Mudança de metodologia em
relação aos testes multi-fase anteriores (`ragas_contextual/resultados/metricas_contextual.json`),
que avaliavam os 4 logs sintéticos completos (Reconnaissance → ... → Stealth) de uma vez.

22 cenários de fase única foram gerados extraindo cada fase individual dos 4 logs
multifase originais (linux-syslog, macos-unified-log, rede, windows-eventlog), um
por tática × plataforma (`*-single.log` + `*-single-gabarito.json` em
`ragas_contextual/resultados/`).

## Bugs encontrados e corrigidos durante o processo

1. **Fabricação de fases fantasmas no organizador** (`pipeline_contextual/agente_organizador_fases.py::_parsear_resposta_reduce`).
   O LLM podia referenciar o mesmo `chunk_origem` em várias fases da mesma resposta,
   violando a própria instrução do prompt ("todo id deve aparecer em exatamente uma
   fase"). Resultado: fases fantasmas, todas com o mesmo intervalo de linhas, geradas
   a partir de um único resumo condensado. **Fix**: ids já reivindicados por uma fase
   anterior na mesma resposta passam a ser ignorados em fases seguintes. Validado:
   22/22 cenários passaram a detectar exatamente 1 fase (zero fabricação).

2. **Query de busca sem termos literais** (`pipeline_contextual/agente_resumidor_arquivo.py`).
   O resumidor produzia uma paráfrase abstrata do comportamento, descartando comandos,
   Event IDs e nomes de binário que o corpus MITRE também usa em seus exemplos de
   `texto_busca_vetorial`. Diagnóstico manual (T1007/Discovery): a query original
   colocava a técnica correta na posição #18 do ranking (score 0.53); uma query que
   preservava os termos literais colocou a mesma técnica na posição #1 (score 0.585).
   **Fix**: prompt do resumidor alterado para exigir preservação literal de comandos,
   IDs de evento e nomes de processo/binário no `resumo_comportamental`.

## Configuração usada nesta rodada

| Parâmetro | Valor | Observação |
|---|---|---|
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | trocado de `llama-3.1-8b-instant` |
| `CONTEXTUAL_TOP_K` | 10 | subiu de 5 |
| `CONTEXTUAL_SCORE_THRESHOLD` | 0.45 | inalterado |
| `CONTEXTUAL_CHUNK_SIZE` (neste teste) | tamanho do arquivo | força 1 único chunk por cenário |
| Qdrant | 872/872 técnicas MITRE | coleção `colecao_logs_patterns` |

## Resultado agregado

**Recall médio: 28,3%** (22/22 cenários) — baseline pré-fix era **5%**. Melhora de ~5,7x.

| Tática | Recall médio | n |
|---|---:|---:|
| Discovery | 75,0% | 4 |
| Reconnaissance | 40,0% | 2 |
| Privilege Escalation | 28,0% | 4 |
| Stealth | 16,7% | 4 |
| Execution | 16,1% | 4 |
| **Initial Access** | **0,0%** | 4 |

## Detalhe completo (22 cenários)

| Cenário | Tática | Recall | Técnicas acertadas |
|---|---|---:|---|
| linux-syslog-discovery | Discovery | 0,0% | — |
| macos-unified-log-discovery | Discovery | 100,0% | T1007 |
| rede-discovery | Discovery | 100,0% | T1040 |
| windows-eventlog-discovery | Discovery | 100,0% | T1007 |
| linux-syslog-reconnaissance | Reconnaissance | 80,0% | T1590, T1590.001, T1590.005, T1596.002 |
| rede-reconnaissance | Reconnaissance | 0,0% | — |
| linux-syslog-privilege-escalation | Privilege Escalation | 66,7% | T1078.001, T1098, T1098.004, T1098.007 |
| macos-unified-log-privilege-escalation | Privilege Escalation | 28,6% | T1078, T1098.004 |
| rede-privilege-escalation | Privilege Escalation | 16,7% | T1098.004 |
| windows-privesc | Privilege Escalation | 0,0% | — |
| rede-stealth | Stealth | 66,7% | T1027, T1027.003 |
| linux-syslog-stealth | Stealth | 0,0% | — |
| macos-unified-log-stealth | Stealth | 0,0% | — |
| windows-eventlog-stealth | Stealth | 0,0% | — |
| linux-syslog-execution | Execution | 16,7% | T1569 |
| macos-unified-log-execution | Execution | 14,3% | T1059.002 |
| rede-execution | Execution | 16,7% | T1053.007 |
| windows-eventlog-execution | Execution | 16,7% | T1569.002 |
| linux-syslog-initial-access | Initial Access | 0,0% | — |
| macos-unified-log-initial-access | Initial Access | 0,0% | — |
| rede-initial-access | Initial Access | 0,0% | — |
| windows-eventlog-initial-access | Initial Access | 0,0% | — |

Dados brutos completos (títulos de fase gerados, técnicas recuperadas por cenário) em
`resumo_cenarios_fase_unica_v2.json`.

## Achados principais

- **O fix funcionou e generalizou**: a melhora de 5% → 28,3% se sustenta nas 4
  plataformas, não é um efeito isolado do cenário de diagnóstico (Windows/T1007).
- **Discovery e Reconnaissance se beneficiam mais**: são táticas com comandos e
  artefatos bem específicos (`tasklist`, `sc query`, `nmap`, etc.), que o embedding
  consegue casar bem quando preservados literalmente na query.
- **Initial Access falhou 100% das vezes, nas 4 plataformas** — padrão sistemático,
  não ruído. Hipótese não testada: as técnicas de Initial Access (phishing,
  exploração de serviço exposto) tendem a ser mais comportamentais/contextuais do
  que baseadas em um comando específico, então preservar "termos literais" ajuda
  menos — vale investigar como um próximo passo.
- **Execution ficou consistentemente baixo (~16%) em todas as plataformas** — pode
  indicar um problema mais estrutural nessa tática (ex: corpus MITRE de Execution
  desbalanceado ou pouco distintivo), diferente da variação alta vista em outras
  táticas (ex: Stealth, que vai de 0% a 67% dependendo da plataforma).

## Próximos passos sugeridos

1. Investigar por que Initial Access não recupera nada em nenhuma plataforma.
2. Recalcular as métricas do cenário **multi-fase** original (`metricas_contextual.json`)
   com os mesmos fixes, agora que o comportamento de fase única está bem caracterizado.
3. Considerar `CONTEXTUAL_TOP_K` ainda maior ou um modelo de embedding melhor para o
   domínio de técnicas MITRE, já que os scores do corpus inteiro ficam muito
   próximos entre si (~0.50–0.58), dificultando a discriminação.
