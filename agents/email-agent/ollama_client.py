import requests

OLLAMA_URL = "http://ollama:11434/api/generate"
MODEL = "phi"

def query_ollama(prompt: str) -> str:
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    }

    r = requests.post(OLLAMA_URL, json=payload, timeout=120)
    r.raise_for_status()

    return r.json()["response"]
