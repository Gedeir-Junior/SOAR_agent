import json
import re
import logging
from rags.prompts import build_prompt
from ollama_client import query_ollama
from scheme import EmailClassification

logger = logging.getLogger("email_agent")

def safe_json_parse(text: str) -> dict:
    """Extrai JSON mesmo se o LLM retornar texto extra.

    Melhora tolerância a saídas comuns do LLM: texto adicional, vírgula final,
    falta de chaves de fechamento, chaves sem aspas, aspas simples e valores
    booleanos com capitalização Python. Se não for possível reparar, tenta
    extrair campos-chave via regex e compõe uma classificação parcial.
    """
    s = text.strip()

    # Primeiro, tentativa direta
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass

    # Encontra início do JSON
    start = s.find('{')
    if start == -1:
        raise ValueError("No JSON object found in LLM output")

    fragment = s[start:]

    # Heurísticas de normalização
    # 1) Adiciona '}' se estiver faltando
    if '}' not in fragment:
        fragment = fragment.rstrip() + '}'

    # 2) Remove vírgulas finais antes de } ou ]
    fragment = re.sub(r',\s*([}\]])', r'\1', fragment)

    # 3) Converte aspas simples para duplas (cuidado com apostrofes dentro de texto)
    fragment = fragment.replace("'", '"')

    # 4) Adiciona aspas em chaves sem aspas: {key: -> {"key":
    fragment = re.sub(r'(?P<pre>[{,\[]\s*)(?P<key>[A-Za-z_][A-Za-z0-9_-]*)\s*:', r"\g<pre>\"\g<key>\":", fragment)

    # 5) Converte True/False/None -> true/false/null
    fragment = re.sub(r'\bTrue\b', 'true', fragment)
    fragment = re.sub(r'\bFalse\b', 'false', fragment)
    fragment = re.sub(r'\bNone\b', 'null', fragment)

    try:
        return json.loads(fragment)
    except json.JSONDecodeError:
        # Fallback: tenta extrair campos-chave mesmo se o JSON estiver incompleto
        parsed = {}

        # label
        m = re.search(r'"?label"?\s*:\s*"?([a-zA-Z_]+)"?', s, re.IGNORECASE)
        if m:
            parsed['label'] = m.group(1).lower()

        # confidence
        m = re.search(r'"?confidence"?\s*:\s*([0-9]*\.?[0-9]+)', s, re.IGNORECASE)
        if m:
            try:
                parsed['confidence'] = float(m.group(1))
            except ValueError:
                parsed['confidence'] = 0.0

        # has_malicious_url
        m = re.search(r'"?has_malicious_url"?\s*:\s*(true|false|True|False)', s)
        if m:
            parsed['has_malicious_url'] = m.group(1).lower() == 'true'

        # indicators: tenta capturar URLs ou itens dentro de colchetes
        m = re.search(r'"?indicators"?\s*:\s*\[([^\]]+)\]', s)
        if m:
            items = re.findall(r'"([^"]+)"|([^,\s]+)', m.group(1))
            indicators = []
            for a, b in items:
                val = a or b
                val = val.strip().strip('"')
                if val:
                    indicators.append(val)
            parsed['indicators'] = indicators
        else:
            # procurar URLs no texto
            urls = re.findall(r'https?://[^\s\]",]+', s)
            if urls:
                parsed['indicators'] = urls

        # recommended_action
        m = re.search(r'"?recommended_action"?\s*:\s*"([^"]+)"', s)
        if m:
            parsed['recommended_action'] = m.group(1)

        # Se não achou nem label, falha
        if 'label' not in parsed:
            raise ValueError("Invalid LLM output after repair attempt: no label found")

        # Campos com valores padrão
        parsed.setdefault('confidence', 0.0)
        parsed.setdefault('indicators', [])
        parsed.setdefault('has_malicious_url', False)
        parsed.setdefault('recommended_action', None)

        return parsed


def classify_email(sender, receiver, date, subject, body):
    query = f"""
    Sender: {sender}
    Receiver: {receiver}
    Date: {date}
    Subject: {subject}
    Body: {body}
    """

    try:
        from rags.retriever import get_reference_material
        references = get_reference_material(query, top_k=5)
    except Exception as e:
        logger.error(f"RAG unavailable, continuing without it: {e}")
        references = "No external reference material available."

    final_prompt = build_prompt(
        references=references,
        sender=sender,
        receiver=receiver,
        date=date,
        subject=subject,
        body=body
    )

    llm_response = query_ollama(prompt=final_prompt)

    parsed = safe_json_parse(llm_response)
    classification = EmailClassification.parse_obj(parsed)

    return classification, llm_response
