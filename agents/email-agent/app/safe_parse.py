import json
import re
import logging
from .schemas import EmailAnalysisResponse

logger = logging.getLogger("email_agent")

def safe_parse_json(text: str):
    # Remove qualquer texto antes ou depois do bloco JSON
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        logger.error("Nenhum JSON encontrado na resposta da LLM.")
        return None, text
    
    cleaned = match.group(0)
    
    try:
        data = json.loads(cleaned)
        # Retorna o objeto validado
        return EmailAnalysisResponse(**data), cleaned
    except Exception as e:
        logger.error(f"Falha na validação Pydantic: {e}")
        return None, text