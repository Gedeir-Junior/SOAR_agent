"""
services/groq_client.py

Helper compartilhado para chamadas ao Groq (chat completions) com parsing de
retry-after e backoff exponencial em 429/erros de rede.

Extraído da lógica duplicada em pipeline/agente_tradutor_logs.py,
pipeline/agent_comparador_ameacas.py e builder/data_set_builder.py. Os agentes
do pipeline_contextual usam este helper desde o início — os arquivos antigos
não foram alterados.
"""
from __future__ import annotations

import os
import re
import time
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL   = os.getenv("GROQ_MODEL", "meta-llama/llama-4-scout-17b-16e-instruct")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
LLM_RETRIES  = int(os.getenv("LLM_RETRIES", "3"))


def parse_retry_after(response: requests.Response) -> float:
    """Extrai o tempo de espera sugerido pelo Groq em respostas 429.

    O formato do header (ex: "1h9m7.2s", "6s", "185ms") mistura unidades —
    precisa checar "ms" ANTES de "m", senão a regex de minutos casa
    greedily com o "m" de "ms" (ex: "185ms" virava 185 MINUTOS)."""
    for header in ("x-ratelimit-reset-requests", "retry-after", "Retry-After"):
        val = response.headers.get(header, "")
        if not val:
            continue

        if re.fullmatch(r"[\d.]+ms", val):
            return min(max(float(val[:-2]) / 1000.0 + 1.0, 5.0), 120.0)

        horas = re.search(r"([\d.]+)h", val)
        minutos = re.search(r"(\d+)m(?!s)", val)
        segundos = re.search(r"([\d.]+)s", val)
        total = 0.0
        if horas:
            total += float(horas.group(1)) * 3600
        if minutos:
            total += int(minutos.group(1)) * 60
        if segundos:
            total += float(segundos.group(1))
        if total > 0:
            return min(max(total + 1.0, 5.0), 120.0)
        try:
            return min(max(float(val) + 1.0, 5.0), 120.0)
        except ValueError:
            pass
    return 30.0


def chamar_groq(
    prompt: str,
    system_prompt: str,
    temperature: float = 0.2,
    modelo: Optional[str] = None,
    origem: str = "groq_client",
) -> str:
    """
    Chama o endpoint de chat completions do Groq com resposta em JSON.

    Args:
        prompt: mensagem do usuário.
        system_prompt: mensagem de sistema (varia por agente/prompt).
        temperature: temperatura da geração.
        modelo: sobrescreve GROQ_MODEL se fornecido.
        origem: rótulo usado nos logs de retry/erro (ex: "resumidor", "organizador").
    """
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY não definida no .env")

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": modelo or GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": prompt},
        ],
        "temperature": temperature,
        "response_format": {"type": "json_object"},
    }

    last_error: Exception | None = None
    for attempt in range(LLM_RETRIES + 1):
        try:
            resp = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=60)
            if resp.status_code == 429:
                wait = parse_retry_after(resp)
                print(f"  [{origem} 429] aguardando {wait:.1f}s…")
                time.sleep(wait)
                attempt = max(attempt - 1, 0)
                continue
            resp.raise_for_status()
            return resp.json()["choices"][0]["message"]["content"]
        except requests.HTTPError as exc:
            last_error = exc
            if attempt < LLM_RETRIES:
                time.sleep(2 ** attempt)
                continue
            break
        except requests.RequestException as exc:
            last_error = exc
            if attempt < LLM_RETRIES:
                time.sleep(2 ** attempt)
                continue
            break

    raise RuntimeError(f"Falha ao consultar Groq ({origem}): {last_error}") from last_error


def extrair_json(raw: str) -> str:
    """Remove blocos ```json ... ``` que o LLM às vezes retorna, apesar do response_format."""
    raw = raw.strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
    return raw
