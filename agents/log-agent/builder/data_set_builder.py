from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import requests
from dotenv import load_dotenv
from pydantic import TypeAdapter, ValidationError

load_dotenv()

BUILDER_DIR = Path(__file__).resolve().parent
if str(BUILDER_DIR) not in sys.path:
    sys.path.insert(0, str(BUILDER_DIR))

from scheme import DatasetManifest, TacticDataset, ThreatDetectionPattern

DEFAULT_OUTPUT_DIR = BUILDER_DIR.parent / "datasets"
DEFAULT_MANIFEST = DEFAULT_OUTPUT_DIR / "manifest.json"

# ---------------------------------------------------------------------------
# Configuração de provider — defina LLM_PROVIDER no .env como "groq" ou "ollama"
# ---------------------------------------------------------------------------
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "groq").lower()

# Groq
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "meta-llama/llama-4-scout-17b-16e-instruct")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"

# Ollama (fallback local)
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_URL = f"{OLLAMA_BASE_URL.rstrip('/')}/api/generate"
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1:latest")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "300"))

# Configurações comuns
MODEL_NAME = GROQ_MODEL if LLM_PROVIDER == "groq" else OLLAMA_MODEL
LLM_RETRIES = int(os.getenv("LLM_RETRIES", "3"))
LLM_WORKERS = int(os.getenv("LLM_WORKERS", "4"))   # threads paralelas
RPM_LIMIT = int(os.getenv("RPM_LIMIT", "25"))       # requisições/minuto

PATTERN_ADAPTER = TypeAdapter(list[ThreatDetectionPattern])

# ---------------------------------------------------------------------------
# Rate limiter compartilhado entre threads
# ---------------------------------------------------------------------------
_rate_lock = threading.Lock()
_request_times: list[float] = []


def _rate_limited_call(fn, *args, **kwargs):
    """Garante que não ultrapassemos RPM_LIMIT req/min."""
    with _rate_lock:
        now = time.monotonic()
        _request_times[:] = [t for t in _request_times if now - t < 60.0]
        if len(_request_times) >= RPM_LIMIT:
            wait_secs = 60.0 - (now - _request_times[0]) + 0.2
            print(f"  [rate-limit] aguardando {wait_secs:.1f}s…")
            time.sleep(wait_secs)
        _request_times.append(time.monotonic())
    return fn(*args, **kwargs)


# ---------------------------------------------------------------------------
# Exemplo concreto de saída — substitui o schema Pydantic no prompt
# ---------------------------------------------------------------------------
_OUTPUT_EXAMPLE = json.dumps(
    [
        {
            "tecnica_id": "T1595.001",
            "nome_tecnica": "Active Scanning: Scanning IP Blocks",
            "tatica": "Reconnaissance",
            "tatica_id": "TA0043",
            "descricao_mitre": "Adversaries scan IP blocks to discover live hosts.",
            "descricao_semantica_log": (
                "Picos de conexoes TCP SYN sem ACK correspondente originadas de um unico "
                "IP externo em curto intervalo. Firewall registra centenas de tentativas "
                "para portas sequenciais (22, 80, 443, 3389). IDS detecta assinatura de "
                "varredura nmap/masscan pelo TTL e janela TCP atipicos."
            ),
            "plataformas_mitre": ["Network"],
            "is_subtecnica": True,
            "tecnica_pai_id": "T1595",
            "padroes_log": [
                {
                    "fonte": "rede",
                    "exemplos": [
                        "2025-03-12T08:14:22Z SRC=198.51.100.7 DST=10.10.1.1 SPT=61234 DPT=22 SYN",
                        "2025-07-04T22:03:55Z SRC=203.0.113.42 DST=10.10.1.5 SPT=49812 DPT=443 SYN",
                    ],
                    "event_ids": [],
                    "indicadores_regex": ["SYN(?!.*ACK).*DPT=(22|80|443|3389|8080)"],
                },
                {
                    "fonte": "linux_syslog",
                    "exemplos": ["Nao aplicavel para esta plataforma"],
                    "event_ids": [],
                    "indicadores_regex": [],
                },
                {
                    "fonte": "windows_eventlog",
                    "exemplos": ["Nao aplicavel para esta plataforma"],
                    "event_ids": [],
                    "indicadores_regex": [],
                },
                {
                    "fonte": "macos_unified_log",
                    "exemplos": ["Nao aplicavel para esta plataforma"],
                    "event_ids": [],
                    "indicadores_regex": [],
                },
            ],
            "palavras_chave_filtro": ["SYN", "nmap", "masscan", "port scan", "RST"],
            "severidade_sugerida": "medium",
            "confianca_padrao": 0.75,
        }
    ],
    ensure_ascii=False,
    indent=2,
)

_SYSTEM_PROMPT = (
    "Você é um sistema automatizado de backend especializado em Engenharia de Detecção (Blue Team). "
    "Sua saída deve ser ESTRITAMENTE um array JSON válido. "
    "Nunca adicione explicações, preâmbulos, comentários ou blocos markdown."
)


# ---------------------------------------------------------------------------
# Dataclasses MITRE
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class MitreTechnique:
    tecnica_id: str
    nome: str
    descricao: str
    is_subtecnica: bool
    tecnica_pai_id: str | None
    plataformas: list[str]
    url: str | None


@dataclass(frozen=True)
class MitreTactic:
    tatica_id: str
    nome: str
    tecnicas: list[MitreTechnique]


# ---------------------------------------------------------------------------
# Helpers STIX
# ---------------------------------------------------------------------------
def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")
    return slug or "unknown"


def _normalize_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _external_id(obj: dict[str, Any], source_name: str = "mitre-attack") -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source_name:
            return ref.get("external_id")
    return None


def _external_url(obj: dict[str, Any], source_name: str = "mitre-attack") -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source_name:
            return ref.get("url")
    return None


# ---------------------------------------------------------------------------
# STIX parsing
# ---------------------------------------------------------------------------
def load_stix_bundle(stix_path: Path) -> dict[str, Any]:
    with stix_path.open(encoding="utf-8") as handle:
        bundle = json.load(handle)
    if bundle.get("type") != "bundle" or "objects" not in bundle:
        raise ValueError("Arquivo STIX inválido: esperado bundle com campo 'objects'.")
    return bundle


def parse_mitre_tactics(bundle: dict[str, Any]) -> dict[str, MitreTactic]:
    objects = bundle["objects"]
    tactic_by_id: dict[str, MitreTactic] = {}
    tactic_by_slug: dict[str, MitreTactic] = {}
    technique_by_stix_id: dict[str, MitreTechnique] = {}
    parent_by_sub_id: dict[str, str] = {}

    for obj in objects:
        if obj.get("type") != "x-mitre-tactic" or obj.get("revoked"):
            continue
        tatica_id = _external_id(obj)
        if not tatica_id:
            continue
        tactic = MitreTactic(tatica_id=tatica_id, nome=obj.get("name", tatica_id), tecnicas=[])
        tactic_by_id[obj["id"]] = tactic
        tactic_by_slug[_normalize_key(tactic.nome)] = tactic

    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked"):
            continue
        if obj.get("x_mitre_deprecated"):
            continue
        tecnica_id = _external_id(obj)
        if not tecnica_id:
            continue
        technique = MitreTechnique(
            tecnica_id=tecnica_id,
            nome=obj.get("name", tecnica_id),
            descricao=(obj.get("description") or "").strip(),
            is_subtecnica=bool(obj.get("x_mitre_is_subtechnique")),
            tecnica_pai_id=None,
            plataformas=list(obj.get("x_mitre_platforms") or []),
            url=_external_url(obj),
        )
        technique_by_stix_id[obj["id"]] = technique

    for rel in objects:
        if rel.get("type") != "relationship":
            continue
        if rel.get("relationship_type") != "subtechnique-of":
            continue
        sub_stix_id = rel.get("source_ref")
        parent_stix_id = rel.get("target_ref")
        parent = technique_by_stix_id.get(parent_stix_id or "")
        if parent and sub_stix_id in technique_by_stix_id:
            parent_by_sub_id[sub_stix_id] = parent.tecnica_id

    for stix_id, parent_id in parent_by_sub_id.items():
        technique = technique_by_stix_id.get(stix_id)
        if technique:
            technique_by_stix_id[stix_id] = MitreTechnique(
                tecnica_id=technique.tecnica_id,
                nome=technique.nome,
                descricao=technique.descricao,
                is_subtecnica=technique.is_subtecnica,
                tecnica_pai_id=parent_id,
                plataformas=technique.plataformas,
                url=technique.url,
            )

    def _assign(technique: MitreTechnique, tactic: MitreTactic) -> None:
        if any(item.tecnica_id == technique.tecnica_id for item in tactic.tecnicas):
            return
        tactic.tecnicas.append(technique)

    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked"):
            continue
        if obj.get("x_mitre_deprecated"):
            continue
        technique = technique_by_stix_id.get(obj["id"])
        if not technique:
            continue
        linked = False
        for tactic_ref in obj.get("x_mitre_tactic_refs") or []:
            tactic = tactic_by_id.get(tactic_ref)
            if tactic:
                _assign(technique, tactic)
                linked = True
        for phase in obj.get("kill_chain_phases") or []:
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            tactic = tactic_by_slug.get(_normalize_key(phase.get("phase_name", "")))
            if tactic:
                _assign(technique, tactic)
                linked = True
        if not linked:
            continue

    for tactic in tactic_by_id.values():
        tactic.tecnicas.sort(key=lambda item: item.tecnica_id)

    return {tactic.tatica_id: tactic for tactic in tactic_by_id.values()}


def resolve_tactic(tactics: dict[str, MitreTactic], selector: str) -> MitreTactic:
    normalized = selector.strip().lower()
    if normalized.upper().startswith("TA") and normalized.upper() in tactics:
        return tactics[normalized.upper()]
    for tactic in tactics.values():
        if tactic.tatica_id.lower() == normalized:
            return tactic
        if _slugify(tactic.nome) == _slugify(selector):
            return tactic
        if tactic.nome.lower() == normalized:
            return tactic
    available = ", ".join(f"{t.nome} ({t.tatica_id})" for t in tactics.values())
    raise ValueError(f"Tática '{selector}' não encontrada. Disponíveis: {available}")


def _chunked(items: list[MitreTechnique], size: int) -> Iterable[list[MitreTechnique]]:
    for index in range(0, len(items), size):
        yield items[index : index + size]


# ---------------------------------------------------------------------------
# Prompt — usa exemplo concreto em vez do schema Pydantic
# ---------------------------------------------------------------------------
def build_prompt(tactic: MitreTactic, batch: list[MitreTechnique]) -> str:
    tecnicas_json = [
        {
            "tecnica_id": tech.tecnica_id,
            "nome_tecnica": tech.nome,
            "tatica": tactic.nome,
            "tatica_id": tactic.tatica_id,
            "descricao_mitre": tech.descricao,
            "plataformas_mitre": tech.plataformas,
            "is_subtecnica": tech.is_subtecnica,
            "tecnica_pai_id": tech.tecnica_pai_id,
        }
        for tech in batch
    ]

    n = len(batch)
    return f"""Tática atual: {tactic.nome} ({tactic.tatica_id})

CAMPO "fonte" — use EXATAMENTE um destes 4 valores (nenhum outro é aceito):
  "linux_syslog"      — Linux, auditd, sshd, processos locais
  "windows_eventlog"  — Windows Event Log, Sysmon
  "macos_unified_log" — macOS Endpoint Security, Unified Log
  "rede"              — tráfego de rede, firewall, IDS/IPS
NÃO use: "network", "kubernetes", "cloud", "azure", "aws", "docker", "k8s", etc.
Técnicas de Containers/Cloud que não se encaixam: use ["Não aplicável para esta plataforma"].

REGRAS:
1. Se a técnica não gera logs em uma fonte: exemplos: ["Não aplicável para esta plataforma"], event_ids: [].
2. palavras_chave_filtro: termos técnicos reais (Event IDs como string "4688", comandos, protocolos). Sem IPs genéricos ou usuários fictícios.
3. descricao_semantica_log: mínimo 50 palavras descrevendo telemetria específica.
4. event_ids: sempre lista de STRINGS — ["4688", "4625"], nunca inteiros [4688].
5. confianca_padrao: float 0.0–1.0, nunca percentual.
6. Retorne exatamente {n} objeto(s) no array — um por técnica fornecida.

Técnicas a processar:
{json.dumps(tecnicas_json, ensure_ascii=False, indent=2)}

Siga estritamente a estrutura deste exemplo de saída:
{_OUTPUT_EXAMPLE}
"""


# ---------------------------------------------------------------------------
# Providers LLM
# ---------------------------------------------------------------------------
def _query_groq(prompt: str) -> str:
    if not GROQ_API_KEY:
        raise RuntimeError("GROQ_API_KEY não definida no .env")

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }

    last_error: Exception | None = None
    for attempt in range(LLM_RETRIES + 1):
        try:
            response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            text = data["choices"][0]["message"]["content"]
            if not text:
                raise RuntimeError("Resposta vazia do Groq.")
            return text
        except requests.HTTPError as exc:
            # 429 = rate limit do Groq — espera mais
            if exc.response is not None and exc.response.status_code == 429:
                wait = 10 * (attempt + 1)
                print(f"  [groq 429] aguardando {wait}s…")
                time.sleep(wait)
                last_error = exc
                continue
            raise
        except (requests.RequestException, RuntimeError) as exc:
            last_error = exc
            if attempt < LLM_RETRIES:
                time.sleep(2**attempt)
                continue
            break

    raise RuntimeError(f"Falha ao consultar Groq: {last_error}") from last_error


def _query_ollama(prompt: str) -> str:
    payload = {
        "model": OLLAMA_MODEL,
        "system": _SYSTEM_PROMPT,
        "prompt": prompt,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.1, "top_p": 0.9},
    }

    last_error: Exception | None = None
    for attempt in range(LLM_RETRIES + 1):
        try:
            response = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
            response.raise_for_status()
            text = response.json().get("response", "")
            if not text:
                raise RuntimeError("Resposta vazia do Ollama.")
            return text
        except (requests.RequestException, RuntimeError) as exc:
            last_error = exc
            if attempt < LLM_RETRIES:
                time.sleep(1 + attempt * 2)
                continue
            break

    raise RuntimeError(f"Falha ao consultar Ollama: {last_error}") from last_error


def query_llm(prompt: str) -> str:
    """Despacha para o provider configurado em LLM_PROVIDER."""
    if LLM_PROVIDER == "groq":
        return _query_groq(prompt)
    elif LLM_PROVIDER == "ollama":
        return _query_ollama(prompt)
    else:
        raise ValueError(f"LLM_PROVIDER inválido: '{LLM_PROVIDER}'. Use 'groq' ou 'ollama'.")


# ---------------------------------------------------------------------------
# Extração e validação do JSON retornado pelo modelo
# ---------------------------------------------------------------------------
def _extract_json_array(raw: str) -> Any:
    raw = raw.strip()
    # Remove blocos markdown se o modelo ignorar a instrução
    if raw.startswith("```"):
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)

    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return parsed
        # Groq com json_object às vezes envolve em {"padroes": [...]} ou {"data": [...]}
        for key in ("padroes", "data", "patterns", "results", "tecnicas"):
            if key in parsed and isinstance(parsed[key], list):
                return parsed[key]
        # Objeto único → envolve em lista
        return [parsed]
    except json.JSONDecodeError:
        pass

    match = re.search(r"\[[\s\S]*\]", raw)
    if not match:
        raise ValueError("Não foi possível extrair JSON da resposta do modelo.")
    return json.loads(match.group(0))


def generate_patterns_for_batch(
    tactic: MitreTactic,
    batch: list[MitreTechnique],
) -> list[ThreatDetectionPattern]:
    prompt = build_prompt(tactic, batch)

    # Rate limiting aplicado antes de cada chamada real
    raw = _rate_limited_call(query_llm, prompt)
    payload = _extract_json_array(raw)

    try:
        patterns = PATTERN_ADAPTER.validate_python(payload)
    except ValidationError as exc:
        raise ValueError(
            f"Resposta inválida para lote {[t.tecnica_id for t in batch]}: {exc}"
        ) from exc

    expected_ids = {tech.tecnica_id for tech in batch}
    received_ids = {pattern.tecnica_id for pattern in patterns}
    missing = expected_ids - received_ids
    if missing:
        raise ValueError(f"Modelo não retornou técnicas: {sorted(missing)}")

    return patterns


# ---------------------------------------------------------------------------
# Persistência
# ---------------------------------------------------------------------------
def load_existing_dataset(path: Path) -> TacticDataset | None:
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as handle:
        return TacticDataset.model_validate_json(handle.read())


def save_dataset(path: Path, dataset: TacticDataset) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dataset.model_dump_json(indent=2), encoding="utf-8")


def update_manifest(
    manifest_path: Path,
    stix_path: Path,
    tactics: dict[str, MitreTactic],
    completed_slug: str,
    total_patterns: int,
) -> None:
    manifest = DatasetManifest(
        stix_arquivo=str(stix_path),
        taticas_concluidas=[],
        taticas_pendentes=[],
        total_padroes=0,
    )
    if manifest_path.exists():
        manifest = DatasetManifest.model_validate_json(
            manifest_path.read_text(encoding="utf-8")
        )
    completed = set(manifest.taticas_concluidas)
    completed.add(completed_slug)
    all_slugs = {_slugify(tactic.nome) for tactic in tactics.values()}
    manifest.taticas_concluidas = sorted(completed)
    manifest.taticas_pendentes = sorted(all_slugs - completed)
    manifest.total_padroes = total_patterns
    manifest.atualizado_em = datetime.now(timezone.utc)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# Orquestração com paralelismo
# ---------------------------------------------------------------------------
def build_tactic_dataset(
    tactic: MitreTactic,
    *,
    batch_size: int,
    resume: bool,
    output_file: Path,
    limit: int | None = None,
) -> TacticDataset:
    existing = load_existing_dataset(output_file) if resume else None
    done_ids = {item.tecnica_id for item in existing.padroes} if existing else set()

    pending = [tech for tech in tactic.tecnicas if tech.tecnica_id not in done_ids]
    if limit is not None:
        pending = pending[:limit]

    collected: list[ThreatDetectionPattern] = list(existing.padroes) if existing else []
    collect_lock = threading.Lock()

    print(
        f"Tática {tactic.nome} ({tactic.tatica_id}): "
        f"{len(tactic.tecnicas)} técnicas no STIX, {len(pending)} pendentes."
    )
    print(f"Provider: {LLM_PROVIDER.upper()} | Workers: {LLM_WORKERS} | RPM limit: {RPM_LIMIT}")

    if not pending:
        raise ValueError(
            f"Nenhuma técnica pendente para '{tactic.nome}'. "
            "Use --resume se deseja continuar ou remova o arquivo existente."
        )

    batches = list(_chunked(pending, batch_size))

    def process(index_batch: tuple[int, list[MitreTechnique]]) -> list[ThreatDetectionPattern]:
        index, batch = index_batch
        ids = ", ".join(t.tecnica_id for t in batch)
        print(f"  Lote {index}/{len(batches)}: {ids}")
        return generate_patterns_for_batch(tactic, batch)

    with ThreadPoolExecutor(max_workers=LLM_WORKERS) as executor:
        futures = {
            executor.submit(process, (i, batch)): batch
            for i, batch in enumerate(batches, start=1)
        }
        for future in as_completed(futures):
            batch = futures[future]
            try:
                patterns = future.result()
            except ValueError as exc:
                print(f"  [ERRO] {exc}", file=sys.stderr)
                continue

            with collect_lock:
                collected.extend(patterns)
                # Salva snapshot parcial a cada lote concluído
                partial = TacticDataset(
                    tatica=tactic.nome,
                    tatica_id=tactic.tatica_id,
                    modelo_llm=MODEL_NAME,
                    padroes=collected,
                )
                save_dataset(output_file, partial)

    return TacticDataset(
        tatica=tactic.nome,
        tatica_id=tactic.tatica_id,
        modelo_llm=MODEL_NAME,
        padroes=collected,
    )


def count_total_patterns(output_dir: Path) -> int:
    total = 0
    for file in output_dir.glob("*.json"):
        if file.name == "manifest.json":
            continue
        try:
            dataset = TacticDataset.model_validate_json(file.read_text(encoding="utf-8"))
        except ValidationError:
            continue
        total += len(dataset.padroes)
    return total


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Gera dataset de padrões de log por tática MITRE usando LLM.",
    )
    parser.add_argument(
        "--stix-path",
        type=Path,
        required=True,
        help="Caminho para enterprise-attack.json (bundle STIX do MITRE ATT&CK).",
    )
    parser.add_argument(
        "--tactic",
        required=True,
        help="Tática alvo: nome (Reconnaissance), slug ou ID (TA0043).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Diretório de saída dos datasets.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1,
        help="Técnicas por chamada à API (padrão: 1).",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Continua arquivo existente, ignorando técnicas já geradas.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Limita quantas técnicas processar (útil para testes).",
    )
    parser.add_argument(
        "--list-tactics",
        action="store_true",
        help="Lista táticas disponíveis no STIX e encerra.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.batch_size < 1:
        print("--batch-size deve ser >= 1", file=sys.stderr)
        return 1

    if not args.stix_path.exists():
        print(f"Arquivo STIX não encontrado: {args.stix_path}", file=sys.stderr)
        return 1

    bundle = load_stix_bundle(args.stix_path)
    tactics = parse_mitre_tactics(bundle)

    if args.list_tactics:
        for tactic in sorted(tactics.values(), key=lambda item: item.tatica_id):
            print(f"{tactic.tatica_id}\t{tactic.nome}\t{len(tactic.tecnicas)} técnicas")
        return 0

    tactic = resolve_tactic(tactics, args.tactic)
    output_file = args.output_dir / f"{_slugify(tactic.nome)}.json"

    try:
        dataset = build_tactic_dataset(
            tactic,
            batch_size=args.batch_size,
            resume=args.resume,
            output_file=output_file,
            limit=args.limit,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    save_dataset(output_file, dataset)

    manifest_path = args.output_dir / "manifest.json"
    total_patterns = count_total_patterns(args.output_dir)
    update_manifest(manifest_path, args.stix_path, tactics, _slugify(tactic.nome), total_patterns)

    print(f"\nDataset salvo em: {output_file}")
    print(f"Padrões gerados nesta tática: {len(dataset.padroes)}")
    print(f"Manifest atualizado: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())