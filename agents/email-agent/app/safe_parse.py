import json
import re

def safe_json_parse(text: str) -> dict:
    """
    Safely parse a JSON string from the given text.
    
    Args:
        text (str): The input text containing a JSON string.
    """

    if not text or not text.strip():
        raise ValueError("Input text is empty or whitespace.")
    raw = text.strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    match = re.search(r'\{.*\}', raw, re.DOTALL)
    if not match:
        raise ValueError("No JSON object found in the text.")
    
    candidate = match.group(0)

    candidate = candidate.replace("'", '"')
    candidate = re.sub(r",\s*}", "}", candidate)
    candidate = re.sub(r",\s*]", "]", candidate)

    candidate = re.sub(r"\bTrue\b", "true", candidate)
    candidate = re.sub(r"\bFalse\b", "false", candidate)
    candidate = re.sub(r"\bNone\b", "null", candidate)

    try:
        return json.loads(candidate)
    except json.JSONDecodeError as e:
        raise ValueError("Failed to parse JSON from the text.") from e
    
    