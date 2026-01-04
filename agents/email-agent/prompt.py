def build_prompt(sender, receiver, date, subject, body):
    return f"""
You are a cybersecurity email classification agent.
You think like a SOC analyst.

STRICT RULES (MANDATORY):
- Output ONLY valid JSON
- Use DOUBLE QUOTES for all keys and string values
- Do NOT include markdown
- Do NOT include explanations
- Do NOT include comments
- Do NOT include trailing commas

You must follow this JSON schema EXACTLY:

{{
  "label": "phishing" | "legitimate",
  "confidence": 0.0,
  "indicators": ["string"],
  "has_malicious_url": false,
  "recommended_action": "string"
}}

Email to analyze:

Sender: {sender}
Receiver: {receiver}
Date: {date}
Subject: {subject}

Body:
{body}

Return ONLY the JSON object.
"""
