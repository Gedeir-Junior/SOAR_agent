from prompts.email_classification import build_email_classification_prompt
from app.safe_parse import safe_parse_json
from app.schemas import EmailAnalysisResponse
from rag.retrievers import retrieve_rag_context
import requests

def classify_email(email_data: dict):
    # 1. Truncamos APENAS o corpo para evitar estouro de contexto/timeout
    # O sender, subject e links permanecem integrais
    body_content = email_data.get('body', '')
    truncated_body = body_content[:1500] if len(body_content) > 1500 else body_content
    
    # 2. Busca Contexto (RAG) baseada no corpo (ou no que for mais relevante)
    context = retrieve_rag_context(truncated_body)
    
    # 3. Montagem do Prompt
    # Passamos o dicionário original, mas com o corpo controlado
    payload_for_prompt = {
        "sender": email_data.get("sender", "Desconhecido"),
        "subject": email_data.get("subject", "Sem Assunto"),
        "body": truncated_body,
        "links": email_data.get("links", []) # Mantém todos os links detectados
    }

    prompt = build_email_classification_prompt(
        guidelines=context['guidelines'],
        examples=context['examples'],
        email=payload_for_prompt
    )
    # ... segue a chamada para o Ollama

    # Chamada ao Ollama/Local LLM
    response = requests.post(
        "http://localhost:11434/api/generate", # Ajuste para sua URL do Ollama
        json={"model": "mistral", "prompt": prompt, "stream": False, "format": "json"},
        timeout=120
    )
    
    raw_text = response.json().get("response", "")
    validated_obj, original_text = safe_parse_json(raw_text)
    
    return validated_obj, original_text