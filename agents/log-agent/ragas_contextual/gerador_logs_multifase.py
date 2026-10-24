"""
ragas_contextual/gerador_logs_multifase.py

Gera logs sintéticos MULTI-FASE (narrativa coerente e ordenada), diferente de
ragas/gerador_logs_siteticos.py, que embaralha linhas soltas por arquivo — bom
para testar classificação linha-a-linha, mas inútil para testar detecção de
fases comportamentais, já que não há sequência de ataque real.

Aqui cada arquivo é construído como uma sequência de blocos contíguos, um por
tática, na ordem de um incidente plausível:

    Reconnaissance -> Initial Access -> Discovery -> Privilege Escalation
    -> Execution -> Stealth

(essas são as 6 táticas com padrões disponíveis em ./datasets — não há dataset
de Persistence/Exfiltration/C2 ainda, então o cenário fica limitado a elas).

Reaproveita de ragas/gerador_logs_siteticos.py: bancos de variação (IPs,
usuários, hostnames), _variar_linha, _adicionar_prefixo, BENIGNAS_POR_FONTE,
carregar_padroes e FONTES_SUPORTADAS — nada disso é duplicado.

Para cada fase, o gabarito registra linha_inicio/linha_fim REAIS (calculados
aqui, não pelo LLM) e o conjunto de tecnica_id plantadas naquele bloco — usado
depois por construtor_dataset_contextual.py para medir Context Precision/Recall
do AgenteComparadorContextual.
"""
from __future__ import annotations

import dataclasses
import json
import random
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from ragas.gerador_logs_siteticos import (
    BENIGNAS_POR_FONTE,
    FONTES_SUPORTADAS,
    MITRE_DATA_DIR_PADRAO,
    SEED,
    _adicionar_prefixo,
    _resolver_arquivos_json,
    _variar_linha,
    carregar_padroes,
)

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
DIRETORIO_SAIDA_PADRAO = Path("./ragas_contextual/resultados")

# Ordem narrativa do cenário — nomes de tática devem bater exatamente com o
# campo "tatica" dos JSONs em ./datasets (ver manifest.json).
CENARIO_TATICAS: list[tuple[str, str]] = [
    ("Reconnaissance", "TA0043"),
    ("Initial Access", "TA0001"),
    ("Discovery", "TA0007"),
    ("Privilege Escalation", "TA0004"),
    ("Execution", "TA0002"),
    ("Stealth", "TA0005"),
]

RATIO_BENIGNAS_PADRAO = 0.15
LINHAS_POR_FASE_PADRAO = 30


# ---------------------------------------------------------------------------
# Dataclasses de gabarito
# ---------------------------------------------------------------------------
@dataclass
class FaseGabarito:
    numero_fase_esperado: int
    tatica_esperada: str
    tatica_id_esperada: str
    linha_inicio: int
    linha_fim: int
    tecnicas_esperadas: list[str] = field(default_factory=list)
    fonte: str = ""


@dataclass
class CenarioMultifase:
    fonte: str
    arquivo_log: str
    total_linhas: int
    fases: list[FaseGabarito] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Amostragem de uma fase (bloco contíguo de linhas de uma única tática)
# ---------------------------------------------------------------------------
def _amostrar_fase(
    padroes_tatica: list[dict],
    fonte: str,
    tamanho: int,
    ratio_benignas: float,
) -> list[tuple[str, str | None]]:
    """Retorna lista de (texto_bruto, tecnica_id_ou_None) para uma fase.

    tecnica_id é None para linhas benignas de preenchimento — elas não entram
    no gabarito de técnicas esperadas da fase, mas ficam misturadas no bloco
    para dar realismo (nem toda linha de uma fase de ataque é maliciosa).
    """
    n_benignas = int(tamanho * ratio_benignas)
    n_ameacas = max(tamanho - n_benignas, 1)

    slots: list[tuple[str, str | None]] = []
    for i in range(n_ameacas):
        p = padroes_tatica[i % len(padroes_tatica)]
        texto = _variar_linha(random.choice(p["exemplos"]))
        slots.append((texto, p["tecnica_id"]))

    linhas_benignas = BENIGNAS_POR_FONTE.get(fonte, ["[benign log entry]"])
    for _ in range(n_benignas):
        slots.append((random.choice(linhas_benignas), None))

    # Embaralha só DENTRO da fase — o bloco continua contíguo no arquivo, o
    # que preserva linha_inicio/linha_fim como fronteiras reais da fase.
    random.shuffle(slots)
    return slots


# ---------------------------------------------------------------------------
# Geração de um cenário completo (um arquivo, uma fonte)
# ---------------------------------------------------------------------------
def gerar_cenario(
    fonte: str,
    padroes_por_fonte: dict[str, list[dict]],
    linhas_por_fase: int = LINHAS_POR_FASE_PADRAO,
    ratio_benignas: float = RATIO_BENIGNAS_PADRAO,
    repeticoes: int = 1,
    seed: int = SEED,
) -> tuple[CenarioMultifase, list[str]]:
    """Gera um cenário multi-fase para `fonte`.

    `repeticoes > 1` repete o ciclo completo de táticas (recon -> ... ->
    stealth -> recon -> ...), útil para gerar arquivos grandes e forçar o
    reduce hierárquico do AgenteOrganizadorFases.
    """
    random.seed(seed)

    padroes_fonte = padroes_por_fonte.get(fonte, [])
    por_tatica: dict[str, list[dict]] = {}
    for p in padroes_fonte:
        por_tatica.setdefault(p["tatica"], []).append(p)

    dt = datetime(2026, 1, 15, 8, 0, 0)
    todas_linhas: list[str] = []
    fases_gabarito: list[FaseGabarito] = []
    numero_linha = 0

    for ciclo in range(repeticoes):
        for tatica, tatica_id in CENARIO_TATICAS:
            padroes_tatica = por_tatica.get(tatica, [])
            if not padroes_tatica:
                if ciclo == 0:
                    print(f"[!] {fonte}: sem padrões para tática '{tatica}', fase pulada.")
                continue

            slots = _amostrar_fase(padroes_tatica, fonte, linhas_por_fase, ratio_benignas)
            linha_inicio = numero_linha + 1
            tecnicas_fase: set[str] = set()

            for texto, tecnica_id in slots:
                numero_linha += 1
                dt += timedelta(seconds=random.randint(1, 20))
                todas_linhas.append(_adicionar_prefixo(texto, fonte, dt))
                if tecnica_id:
                    tecnicas_fase.add(tecnica_id)

            fases_gabarito.append(FaseGabarito(
                numero_fase_esperado=len(fases_gabarito) + 1,
                tatica_esperada=tatica,
                tatica_id_esperada=tatica_id,
                linha_inicio=linha_inicio,
                linha_fim=numero_linha,
                tecnicas_esperadas=sorted(tecnicas_fase),
                fonte=fonte,
            ))

    sufixo = "-multifase" if repeticoes == 1 else f"-multifase-x{repeticoes}"
    nome_base = fonte.replace("_", "-")
    cenario = CenarioMultifase(
        fonte=fonte,
        arquivo_log=f"{nome_base}{sufixo}.log",
        total_linhas=numero_linha,
        fases=fases_gabarito,
    )
    return cenario, todas_linhas


# ---------------------------------------------------------------------------
# Geração de todos os cenários + escrita em disco
# ---------------------------------------------------------------------------
def gerar_todos(
    padroes_por_fonte: dict[str, list[dict]],
    diretorio_saida: Path,
    linhas_por_fase: int = LINHAS_POR_FASE_PADRAO,
    ratio_benignas: float = RATIO_BENIGNAS_PADRAO,
    repeticoes: int = 1,
    seed: int = SEED,
) -> dict[str, Path]:
    diretorio_saida.mkdir(parents=True, exist_ok=True)
    arquivos: dict[str, Path] = {}

    for fonte in FONTES_SUPORTADAS:
        cenario, linhas = gerar_cenario(
            fonte, padroes_por_fonte,
            linhas_por_fase=linhas_por_fase,
            ratio_benignas=ratio_benignas,
            repeticoes=repeticoes,
            seed=seed,
        )
        if not cenario.fases:
            print(f"[!] {fonte}: nenhuma fase gerada, arquivo pulado.")
            continue

        path_log = diretorio_saida / cenario.arquivo_log
        path_log.write_text("\n".join(linhas) + "\n", encoding="utf-8")

        path_gabarito = diretorio_saida / cenario.arquivo_log.replace(".log", "-gabarito.json")
        path_gabarito.write_text(
            json.dumps(dataclasses.asdict(cenario), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        arquivos[fonte] = path_log
        print(
            f"[+] {fonte}: {cenario.total_linhas} linhas, {len(cenario.fases)} fase(s) "
            f"-> {path_log.name}"
        )

    return arquivos


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(
    diretorio_saida: Path = DIRETORIO_SAIDA_PADRAO,
    linhas_por_fase: int = LINHAS_POR_FASE_PADRAO,
    ratio_benignas: float = RATIO_BENIGNAS_PADRAO,
    repeticoes: int = 1,
    json_dir: Path | None = None,
    seed: int = SEED,
) -> dict[str, Path]:
    print("=" * 60)
    print("Gerador de Logs Sintéticos MULTI-FASE — Dataset MITRE ATT&CK")
    print("=" * 60)
    print(f"  Saída            : {diretorio_saida.resolve()}")
    print(f"  Linhas/fase      : {linhas_por_fase}")
    print(f"  Ratio benignas   : {ratio_benignas:.0%}")
    print(f"  Repetições ciclo : {repeticoes}")
    print(f"  Cenário (ordem)  : {' -> '.join(t for t, _ in CENARIO_TATICAS)}")
    print()

    data_dir = json_dir or MITRE_DATA_DIR_PADRAO
    jsons = _resolver_arquivos_json(data_dir)
    padroes = carregar_padroes(jsons)
    for fonte, lista in padroes.items():
        print(f"  {fonte}: {len(lista)} padrões com exemplos reais")
    print()

    arquivos = gerar_todos(
        padroes, diretorio_saida,
        linhas_por_fase=linhas_por_fase,
        ratio_benignas=ratio_benignas,
        repeticoes=repeticoes,
        seed=seed,
    )

    print(f"\n[✓] Cenários multi-fase gerados em: {diretorio_saida.resolve()}")
    return arquivos


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Gera logs sintéticos multi-fase (narrativa ordenada de incidente) "
        "para testar o pipeline_contextual."
    )
    parser.add_argument("--saida", type=Path, default=DIRETORIO_SAIDA_PADRAO)
    parser.add_argument("--linhas-por-fase", type=int, default=LINHAS_POR_FASE_PADRAO)
    parser.add_argument("--ratio-benignas", type=float, default=RATIO_BENIGNAS_PADRAO)
    parser.add_argument(
        "--repeticoes", type=int, default=1,
        help="Repete o ciclo completo de táticas N vezes (gera arquivos grandes "
        "para testar o reduce hierárquico do organizador de fases).",
    )
    parser.add_argument("--json-dir", type=Path, default=None)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    main(
        diretorio_saida=args.saida,
        linhas_por_fase=args.linhas_por_fase,
        ratio_benignas=args.ratio_benignas,
        repeticoes=args.repeticoes,
        json_dir=args.json_dir,
        seed=args.seed,
    )
