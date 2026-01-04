import json
import re
from prompt import build_prompt
from ollama_client import query_ollama
from scheme import EmailClassification

def safe_json_parse(text: str) -> dict:
    """
    Extrai JSON mesmo se o LLM retornar texto extra.
    """
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if not match:
            raise ValueError("No JSON object found in LLM output")

        try:
            return json.loads(match.group())
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid LLM output: {e}")

def classify_email(sender, receiver, date, subject, body):
    prompt = build_prompt(
        sender="sender",
        receiver="receiver",
        date="date",
        subject="subject",
        body="body"
    )


    llm_response = query_ollama(prompt)
    result = safe_json_parse(llm_response)

    return result, llm_response

