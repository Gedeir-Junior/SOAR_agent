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

    return f"""[INST] You are a cybersecurity email analysis engine operating inside a SOAR platform.
Classify the email as "phishing" or "legitimate".

### CONTEXTO DE APOIO (RAG):
DIRETRIZES:
{guidelines or "No guidelines available."}

EXEMPLOS SIMILARES:
Fontes detectadas: {", ".join(sources)}
Contagem: Phishing ({phishing_count}), Legitimate ({legitimate_count})
{chr(10).join(example_snippets)}

### DADOS DO EMAIL:
Sender: {email.get("sender")} | Subject: {email.get("subject")}
Body: {email.get("body")}
Links: {chr(10).join(link_lines)}

### REGRAS DE RESPOSTA:
1. Em 'guidelines_evidence', cite frases curtas das DIRETRIZES acima que o email viola.
2. Em 'sources', escreva exatamente os nomes dos arquivos citados em 'Fontes detectadas': {", ".join(sources)}.
3. Em 'technical_indicators', analise o Sender e os Links fornecidos.

Responda APENAS com o JSON, sem texto explicativo, seguindo este formato:
{{
  "label": "phishing" ou "legitimate",
  "confidence": 0.0,
  "reasoning": {{
    "guidelines_evidence": ["evidência 1", "evidência 2", ...],
    "example_evidence": {{
      "phishing_similar": {phishing_count},
      "legitimate_similar": {legitimate_count},
      "sources": ["{list(sources)[0] if sources else 'unknown'}"]
    }},
    "technical_indicators": ["link suspeito", "remetente falso"]
  }},
  "indicators": ["urgency", "suspicious_link"],
  "has_malicious_url": true,
  "recommended_action": "quarantine"
}}
[/INST]"""