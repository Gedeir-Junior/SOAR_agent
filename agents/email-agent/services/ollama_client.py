import os
import time
import requests
from requests.exceptions import ReadTimeout, RequestException

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434/api/generate")
MODEL = os.getenv("OLLAMA_MODEL", "phi")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "300"))
OLLAMA_RETRIES = int(os.getenv("OLLAMA_RETRIES", "2"))


def query_ollama(prompt: str, **kwargs) -> str:
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    }

    last_exc = None
    for attempt in range(OLLAMA_RETRIES + 1):
        try:
            r = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
            r.raise_for_status()

            data = r.json()
            # Some Ollama setups return different shapes — guard the access
            if "response" in data:
                return data["response"]
            if "results" in data and isinstance(data.get("results"), list):
                return data["results"][0].get("content", "")

            raise RuntimeError("Unexpected Ollama response format")
        except ReadTimeout as e:
            last_exc = e
            if attempt < OLLAMA_RETRIES:
                # exponential backoff
                time.sleep(1 + attempt * 2)
                continue
            raise RuntimeError("Ollama request timed out") from e
        except RequestException as e:
            # Non-retryable network error
            raise RuntimeError(f"Ollama request failed: {e}") from e
    # If we somehow exit loop without returning
    raise RuntimeError("Ollama request failed") from last_exc
