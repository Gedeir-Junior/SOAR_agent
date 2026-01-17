def build_prompt(references, sender, receiver, date, subject, body):
    return f"""
You are a phishing classification engine.

TASK:
Analyze the email and classify it as either "phishing" or "legitimate".

REFERENCE MATERIAL:
{references}

EMAIL DATA:
Sender: {sender}
Receiver: {receiver}
Date: {date}
Subject: {subject}
Body: {body}

STRICT OUTPUT RULES (MANDATORY):
- Respond with VALID JSON ONLY
- Do NOT include explanations
- Do NOT include markdown
- Do NOT include comments
- Do NOT include text before or after the JSON

REQUIRED JSON SCHEMA:
{{
  "label": "phishing" or "legitimate",
  "confidence": 0.0,
  "indicators": [],
  "has_malicious_url": false,
  "recommended_action": "quarantine" or "delete" or "none" or null
}}
"""
