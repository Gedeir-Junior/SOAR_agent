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

    return f"""
You are a cybersecurity email analysis engine operating inside a SOAR platform.

Your task is to classify the email as either "phishing" or "legitimate".
You MUST base your decision ONLY on the evidence provided below.
If evidence is weak or contradictory, LOWER the confidence score.

==================================================
PHISHING IDENTIFICATION GUIDELINES (RAG):
{guidelines or "No guideline data available."}

==================================================
REAL EMAIL EXAMPLES (RAG):
Similar phishing examples: {phishing_count}
Similar legitimate examples: {legitimate_count}
Sources: {", ".join(sources) if sources else "Unknown"}

Examples:
{chr(10).join(example_snippets) if example_snippets else "No similar examples found."}

==================================================
EMAIL CONTENT:
Sender: {email.get("sender")}
Receiver: {email.get("receiver")}
Date: {email.get("date")}
Subject: {email.get("subject")}

Body:
{email.get("body")}

==================================================
TECHNICAL EMAIL SIGNALS:
{chr(10).join(header_lines) if header_lines else "No header data available."}

==================================================
LINK ANALYSIS:
{chr(10).join(link_lines) if link_lines else "No links detected."}

==================================================
ATTACHMENT ANALYSIS:
{chr(10).join(attachment_lines) if attachment_lines else "No attachments detected."}

==================================================
STRICT OUTPUT RULES:
- Output VALID JSON ONLY
- No markdown
- No explanations outside JSON
- Do NOT invent evidence
- Base reasoning on the provided data

==================================================
REQUIRED JSON FORMAT:
{{
  "label": "phishing" or "legitimate",
  "confidence": 0.0,
  "reasoning": {{
    "guideline_evidence": [],
    "example_evidence": {{
      "phishing_similar": 0,
      "legitimate_similar": 0,
      "sources": []
    }},
    "technical_indicators": []
  }},
  "indicators": [],
  "has_malicious_url": false,
  "recommended_action": "quarantine" or "delete" or "none" or null
}}
"""
