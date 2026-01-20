from .pdf_retriever import retrieve_pdf_context
from .example_retriever import retrieve_examples


def retrieve_rag_context(query: str):
    return {
        "guidelines": retrieve_pdf_context(query, k=4),
        "examples": retrieve_examples(query, k=4)
    }
