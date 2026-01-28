def build_email_classification_prompt(
    *,
    guidelines: str,
    examples: list,
    email: dict
):
    """
    Build a SOAR-grade prompt for phishing classification using:
    - RAG guidelines (PDFs)
    - RAG examples (SpamAssassin / CEAS)
    - Technical email signals (headers, links, attachments)
    """

    # =====================
    # Example summarization
    # =====================

    phishing_count = 0
    legitimate_count = 0
    sources = set()
    example_snippets = []

    for ex in examples:
        label = ex.get("metadata", {}).get("label", "unknown").lower()
        source = ex.get("metadata", {}).get("source", "unknown")
        sources.add(source)

        if label in ["phishing", "spam", "malicious"]:
            phishing_count += 1
        elif label in ["legitimate", "ham"]:
            legitimate_count += 1

        example_snippets.append(
            f"- ({label}) {ex['text'][:250].replace(chr(10), ' ')}"
        )

    # =====================
    # Email technical data
    # =====================

    headers = email.get("headers", {})
    links = email.get("links", [])
    attachments = email.get("attachments", [])

    # Headers summary
    header_lines = []
    for key in [
        "from",
        "return_path",
        "reply_to",
        "spf",
        "dkim",
        "dmarc",
        "message_id"
    ]:
        if key in headers:
            header_lines.append(f"{key.upper()}: {headers[key]}")

    # Links summary
    link_lines = []
    for link in links:
        link_lines.append(
            f"- URL: {link.get('url')} | Domain: {link.get('domain')} | "
            f"Shortened: {link.get('shortened', False)}"
        )

    # Attachments summary
    attachment_lines = []
    for att in attachments:
        attachment_lines.append(
            f"- Filename: {att.get('filename')} | Type: {att.get('mime_type')}"
        )

    # =====================
    # Prompt
    # =====================

 # No final da sua função build_email_classification_prompt:

    return f"""[INST] Você é um agente de análise de e-mails de cibersegurança operando dentro de uma plataforma SOAR.
Sua missão é classificar o e-mail como "phishing" ou "legitimate" através de uma análise imparcial e multifatorial.

### CONTEXTO DE APOIO (RAG):
DIRETRIZES RECUPERADAS:
{guidelines or "Nenhuma diretriz específica encontrada para este contexto."}

EXEMPLOS HISTÓRICOS SIMILARES:
Fontes: {", ".join(sources)}
{chr(10).join(example_snippets)}

### DADOS TÉCNICOS DO EMAIL:
Sender: {email.get("sender")} | Subject: {email.get("subject")}
Body: {email.get("body")}
Links Detectados: {chr(10).join(link_lines)}
Anexos: {chr(10).join(attachment_lines)}

### PROTOCOLO DE ANÁLISE (Siga rigorosamente):
1. **Pilar da Imparcialidade**: Não assuma que o e-mail é malicioso apenas por conter termos técnicos (ex: ISO 27001, NIST, Zero Trust). Analise se o autor está apenas discutindo conceitos ou se está tentando induzir uma ação.
2. **Avaliação Dual**: Identifique explicitamente sinais de segurança (tom informativo, remetente conhecido, ausência de links externos) E sinais de ameaça (senso de urgência, links encurtados, inconsistência de remetente).
3. **Uso do RAG**: Utilize os exemplos e diretrizes como guias de comparação, não como vereditos absolutos. Se o e-mail imita o estilo de um exemplo de phishing, mas os indicadores técnicos são seguros, pondere a incerteza.

Responda estritamente em formato JSON:
{{
  "label": "phishing" ou "legitimate",
  "confidence": 0.0,
  "reasoning": {{
    "safety_signals": ["lista de evidências que sugerem que o e-mail é seguro/legítimo"],
    "threat_signals": ["lista de evidências que sugerem que o e-mail é uma ameaça/phishing"],
    "guidelines_match": "como o e-mail se compara às diretrizes fornecidas",
    "final_decision_logic": "explicação lógica de por que uma hipótese prevaleceu sobre a outra"
  }},
  "indicators": ["urgency", "suspicious_link", "technical_discussion", "internal_communication"],
  "has_malicious_url": true ou false,
  "has_spoofed_sender": true ou false,
  "recommended_action": "deliver_to_inbox", "quarantine", ou "mark_as_spam"
}}
[/INST]"""