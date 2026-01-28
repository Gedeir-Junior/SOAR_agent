def build_email_classification_prompt(
    *,
    guidelines: str,
    examples: list,
    email: dict
):
    # 1. Extração de Links (Garante que link_lines não seja vazio)
    links = email.get("links", [])
    link_lines = []
    if isinstance(links, list):
        for link in links:
            # Se for apenas uma string
            if isinstance(link, str):
                link_lines.append(f"- URL: {link}")
            # Se for um dicionário (como no seu sistema SOAR)
            elif isinstance(link, dict):
                url = link.get('url', 'N/A')
                domain = link.get('domain', 'N/A')
                link_lines.append(f"- URL: {url} | Domínio: {domain}")
    
    # 2. Resumo de Exemplos (Limitado para reduzir viés)
    example_snippets = []
    for ex in examples[:4]: # Usamos apenas 4 para não induzir o modelo ao erro
        label = ex.get("metadata", {}).get("label", "desconhecido")
        texto = ex.get("text", "")[:512].replace("\n", " ")
        example_snippets.append(f"- [{label.upper()}]: {texto}...")

    # 3. Prompt Final focado em Imparcialidade
    return f"""[INST] <<SYS>>
Você é um especialista em segurança cibernética focado na em analise de e-mails buscando classificalos em "legítimo" ou "phishing". 
Seja imparcial e objetivo, evitando vieses que possam levar a classificações incorretas, ou seja, não assuma que um email é phishing se ele tem uma característica de phishing.
Use as guidelines como exemplo de boas práticas, mas não se prenda a elas cegamente quero que você desenvolva a própria metodologia.
Além disso compare os exemplos fornecidos com o email analisado para verificar padrões semelhantes, isso pode ajudar a embasar sua decisão.
<</SYS>>

### DOCUMENTOS COM DICAS PARA CLASSIFICAR E-MAILS:
{guidelines}

### REFERÊNCIAS DE COMPARAÇÃO (RAG):
{chr(10).join(example_snippets)}

### DADOS DO E-MAIL ANALISADO:
Remetente: {email.get("sender", "Desconhecido")}
Assunto: {email.get("subject", "Sem Assunto")}
Corpo: {email.get("body", "Corpo vazio")}
Links Detectados: {chr(10).join(link_lines) if link_lines else "Nenhum link detectado."}

### PROTOCOLO DE DECISÃO:
1. Analise a INTENÇÃO: Há uma tentativa de manipulação ou é apenas troca de informação técnica?
2. Se o corpo do e-mail contém links, verifique se eles são suspeitos ou legítimos.
3. Verifique padrões de urgência, ameaças ou solicitações incomuns.
4. Compare com os exemplos fornecidos para identificar similaridades.
5. Caso exista ambiguidade, reflita essa dúvida no índice de confiança, para que possa ser revisado posteriormente.
6. Forneça uma justificativa clara para sua decisão, destacando os principais pontos que influenciaram sua classificação.
7. Recomende a ação apropriada com base na classificação final.
8. Mantenha a imparcialidade em todas as etapas.
9. O objetivo é ajudar a contextualizar o julgamento fornecendo o máximo de detalhes possível e redduzir a carga de trabalho humano.

### TAREFA:
Responda APENAS o JSON:
{{
  "label": "phishing" ou "legitimate",
  "confidence": Entre 0.00 e 1.00 (float),
  "analise_comparativa": {{
    "sinais_de_seguranca": ["evidências de que é legítimo"],
    "sinais_de_ameaca": ["evidências de que é phishing"],
    "justificativa_final": "Racíocinio detalhado por trás da decisão baseado em probabilidades e evidências coletadas."
  }},
  "recommended_action": "deliver_to_inbox" ou "quarantine"
}}
[/INST]"""