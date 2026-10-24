# Status da validação do fix de query literal (06/08/2026)

## Contexto
Fix aplicado em `pipeline_contextual/agente_resumidor_arquivo.py` (prompt do resumidor
passou a exigir preservação literal de comandos/Event IDs/binários, não só parafrasear)
+ `CONTEXTUAL_TOP_K` subiu de 5 para 10 no `.env`. Objetivo: validar se isso melhora o
recall de recuperação de técnicas MITRE nos 22 cenários de fase única
(`*-single.log` / `*-single-gabarito.json` em `ragas_contextual/resultados/`).

Baseline pré-fix (rodada anterior, prompt antigo + top_k=5): **recall médio 5%**,
18/22 cenários com 0% de recall.

## Resultados parciais coletados antes da interrupção

Rodada 1 (execução rápida, sem rate-limit pesado — dados confiáveis):

| Cenário | Recall antes (baseline) | Recall com fix |
|---|---|---|
| linux-syslog-discovery | 0% | 0% |
| linux-syslog-execution | 0% | 17% (T1569) |
| linux-syslog-initial-access | 0% | 0% |
| linux-syslog-privilege-escalation | 0% | **67%** (T1078.001, T1098, T1098.004, T1098.007) |
| linux-syslog-reconnaissance | 0% | **80%** (T1590, T1590.001, T1590.005, T1596.002) |
| linux-syslog-stealth | 0% | 0% |
| macos-unified-log-discovery | 0% | (não terminou — cortado pelo timeout do terminal) |

Rodada 2 (reinício do zero em background, para rodar as 22 completas) — **interrompida
a pedido do usuário após bater rate-limit pesado do Groq** (14+ erros 429, esperas de
120s cada, cenários levando até 972s/16min em vez de ~12s). Só 2 cenários chegaram a
concluir nessa rodada, e AMBOS sofreram falha dura da API Groq no meio do processo
("Falha ao consultar Groq: None"), então os 0% que essa rodada 2 registrou para
linux-syslog-discovery e linux-syslog-execution **não são confiáveis** — refletem
falha de API sob rate-limit, não o desempenho real do fix. (Note: linux-syslog-execution
tinha dado 17% de recall na rodada 1, minutos antes, com o mesmo fix.)

## Log bruto da rodada 2 (parcial, corrompida por rate-limit)
Ver `v2_full.log` seção abaixo seria útil, mas não foi copiado para o repo — só existe
no scratchpad da sessão que rodou isso. Se precisar reexaminar, os comandos usados estão
documentados aqui embaixo em "Como retomar".

## Conclusão até aqui
Os 5 cenários que completaram de forma limpa na Rodada 1 mostram melhora real e forte
em 3 deles (privilege-escalation, reconnaissance, execution — todos linux-syslog),
consistente com a hipótese validada no diagnóstico manual (T1007: rank #18 → #1 ao
preservar termos literais). Ainda não sabemos se isso generaliza para as outras 3
plataformas (macos, rede, windows) nem para discovery/initial-access/stealth, que já
mostravam 0% mesmo no diagnóstico manual mais aprofundado.

## Como retomar
1. Confirmar Qdrant rodando: `docker start qdrant-log-agent`.
2. Rodar o script `/home/gedeirjunior/.../scratchpad/rodar_cenarios_fase_unica.py`
   (salvo em scratchpad de sessão — pode ter sido limpo; recriar se necessário a partir
   da lógica: itera `*-single-gabarito.json` em `ragas_contextual/resultados/`, chama
   `executar_pipeline_contextual_real` com `top_k=10`, `chunk_size=max(total_linhas,40)`,
   calcula recall = interseção entre técnicas esperadas e todas as técnicas recuperadas
   nas fases detectadas).
3. **Considerar reduzir a carga no Groq antes de rodar de novo**: rodar em lotes menores
   (ex: 5 cenários por vez, com pausas), ou aguardar o rate-limit por-minuto resetar,
   ou considerar cair para um modelo intermediário (ex: `openai/gpt-oss-20b`) se
   `llama-3.3-70b-versatile` continuar sendo limitado com tanta frequência.
4. Consolidar os 22 resultados e comparar contra o baseline de 5% de recall médio.
