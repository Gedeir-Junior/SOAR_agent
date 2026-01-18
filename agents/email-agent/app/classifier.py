import logging

from prompts.email_classification import build_email_classification_prompt
from rag.retrievers import retrieve_rag_context
from services.ollama_client import query_ollama
from app.schemas import EmailAnalysisResponse
from app.safe_parse import safe_json_parse

logger = logging.getLogger("email_agent")

def classify_email(email: dict):
    """
    Ponto de entrada principal para classificar um email. (ENDPOINT)
    Orquestra a construção do prompt, recuperação do RAG, chamada do modelo e a validação do outpur.
    """

    # 1. Contruir o query
    query = f"""
    Subject: {email.get('subject')}
    Body: {email.get('body')}
    """

    #2. Recuperar contexto RAG
    try:
        rag_context = retrieve_rag_context(query)
    except Exception as e:
        logger.error(f"Erro ao recuperar contexto RAG: {e}")
        rag_context = {
            "guidelines": "",
            "examples": []
        }
    
    # 3. Construir o prompt
    prompt = build_email_classification_prompt(
        guidelines=rag_context.get("guidelines"),
        examples=rag_context.get("examples",[]),
        email=email
    )

    # 4. Chamar o modelo
    try:
        llm_output = query_ollama(prompt=prompt)
    except Exception as e:
        logger.exception(f"Erro ao chamar o modelo LLM")
        raise RuntimeError("Falha ao chamar o modelo LLM: {e}")

    # 5. Dividir e Validar o output
    try:
        parsed = safe_json_parse(llm_output)
        classification = EmailAnalysisResponse(**parsed)
    except Exception as e:
        logger.exception(f"Erro ao validar o output do modelo")
        raise ValueError(f"Falha ao validar o output do modelo: {e}")
    
    return classification, llm_output