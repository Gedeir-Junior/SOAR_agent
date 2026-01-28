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
    for ex in examples[:2]: # Usamos apenas 2 para não induzir o modelo ao erro
        label = ex.get("metadata", {}).get("label", "desconhecido")
        texto = ex.get("text", "")[:150].replace("\n", " ")
        example_snippets.append(f"- [{label.upper()}]: {texto}...")

    # 3. Prompt Final focado em Imparcialidade
    return f"""[INST] <<SYS>>
Atue como um Analista de Segurança Sénior. Sua tarefa é uma análise forense imparcial.
Assuma que o e-mail pode ser legítimo (comunicação técnica interna). 
Não condene o e-mail apenas por palavras-chave de segurança.
<</SYS>>

### REFERÊNCIAS DE COMPARAÇÃO (RAG):
{chr(10).join(example_snippets)}

### DADOS DO E-MAIL ANALISADO:
Remetente: {email.get("sender", "Desconhecido")}
Assunto: {email.get("subject", "Sem Assunto")}
Corpo: {email.get("body", "Corpo vazio")}
Links Detectados: {chr(10).join(link_lines) if link_lines else "Nenhum link detectado."}

### PROTOCOLO DE DECISÃO:
1. Analise a INTENÇÃO: Há uma tentativa de manipulação ou é apenas troca de informação técnica?
2. Se o remetente for interno e os links apontarem para domínios conhecidos, classifique como "legitimate", mesmo que cite normas (ISO, LGPD).
3. O Phishing geralmente requer uma ação urgente. E-mails técnicos informativos são legítimos.

Responda APENAS o JSON:
{{
  "label": "phishing" ou "legitimate",
  "confidence": 0.0,
  "analise_comparativa": {{
    "sinais_de_seguranca": ["evidências de que é legítimo"],
    "sinais_de_ameaca": ["evidências de que é phishing"],
    "justificativa_final": "por que um lado venceu o outro"
  }},
  "recommended_action": "deliver_to_inbox" ou "quarantine"
}}
[/INST]"""