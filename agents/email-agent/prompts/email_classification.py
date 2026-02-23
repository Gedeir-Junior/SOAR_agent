# email_classification.py otimizado
def build_email_classification_prompt(*, guidelines: str, examples: list, email: dict):
    # Truncagem agressiva para velocidade
    example_snippets = []
    for ex in examples[:2]:
        label = ex.get("metadata", {}).get("label", "desconhecido")
        texto = ex.get("text", "")[:300].replace("\n", " ")
        example_snippets.append(f"- [{label.upper()}]: {texto}")

    return f"""[INST] <<SYS>>
És um analista de segurança imparcial. Classifica o e-mail abaixo.
Não assumes phishing por padrão; procura evidências técnicas.
<</SYS>>

### DIRETRIZES TÉCNICAS:
{guidelines[:800]} 

### EXEMPLOS PARA COMPARAÇÃO:
{chr(10).join(example_snippets)}

### DADOS DO E-MAIL:
Remetente: {email.get("sender")} | Assunto: {email.get("subject")}
Corpo: {email.get("body")}

### TAREFA:
Responda APENAS o JSON:
{{
  "label": "phishing" ou "legitimate"
  "confidence": float,
  "analise_comparativa": {{
    "sinais_de_seguranca": [],
    "sinais_de_ameaca": [],
    "justificativa_final": "Breve análise técnica."
  }},
  "recommended_action": "deliver_to_inbox" ou "quarantine"
}}
[/INST]"""