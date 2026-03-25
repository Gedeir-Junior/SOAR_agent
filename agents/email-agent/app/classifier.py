import requests
import logging
from prompts.email_classification import build_email_classification_prompt
from app.safe_parse import safe_parse_json # Use o nome exato da sua função
from rag.retrievers import retrieve_rag_context

logger = logging.getLogger("email_agent")

def classify_email(email_data: dict):
    # Proteção contra campos nulos que causam falha de fatiamento
    body_content = email_data.get('body') or email_data.get('content') or ""
    truncated_body = body_content[:1500] if len(body_content) > 1500 else body_content
    
    # Criamos o payload seguro para o prompt
    safe_email = {
        "sender": email_data.get("sender") or "Desconhecido",
        "subject": email_data.get("subject") or "Sem Assunto",
        "body": truncated_body,
        "links": email_data.get("links") or []
    }

    try:
        # Busca RAG (limite k=2 para velocidade)
        context = retrieve_rag_context(truncated_body)
        
        prompt = build_email_classification_prompt(
            guidelines=context.get('guidelines', ""),
            examples=context.get('examples', []),
            email=safe_email
        )

        response = requests.post(
            "http://ollama:11434/api/generate",
            json={
                "model": "mistral",
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.0},
                "format": "json" 
            },
            timeout=300
        )
        
        raw_text = response.json().get("response", "")
        # Validação via safe_parse
        return safe_parse_json(raw_text)

    except Exception as e:
        logger.error(f"Erro no pipeline: {e}")
        return None, str(e)