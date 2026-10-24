from __future__ import annotations

import json
import os
import random
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------
SEED = 42
random.seed(SEED)

# Nomes dos JSONs do dataset MITRE (sem path).
# O diretório base é resolvido pelo argumento --json-dir ou MITRE_DATA_DIR.
_SCRIPT_DIR = Path(__file__).resolve().parent.parent
MITRE_DATA_DIR_PADRAO = Path(os.getenv("MITRE_DATA_DIR", str(_SCRIPT_DIR )))

ARQUIVOS_JSON_NOMES = [
    "./datasets/execution.json",
    "./datasets/initial_access.json",
    "./datasets/privilege_escalation.json",
    "./datasets/reconnaissance.json",
    "./datasets/discovery.json",
    "./datasets/stealth.json",
]

def _resolver_arquivos_json(data_dir: Path) -> list[str]:
    return [str(data_dir / nome) for nome in ARQUIVOS_JSON_NOMES]

FONTES_SUPORTADAS = {"linux_syslog", "windows_eventlog", "macos_unified_log", "rede"}

# Proporções padrão (devem somar 1.0)
RATIO_BENIGNAS      = 0.35   # linhas claramente inofensivas
RATIO_FALSOS_POS    = 0.15   # benignas que parecem suspeitas
RATIO_AMEACAS       = 0.50   # linhas de ameaça real

# Diretório padrão de saída (relativo ao CWD; sobrescrito pelo --saida da CLI)
DIRETORIO_SAIDA_PADRAO = Path("./ragas/resultados")


# ---------------------------------------------------------------------------
# Dataclass de saída — inclui tipo e motivo de falso positivo
# ---------------------------------------------------------------------------
@dataclass
class EntradaLog:
    linha_numero: int
    linha_texto: str
    fonte: str
    tecnica_id: str                         # técnica MITRE ou "BENIGNO" / "FALSO_POSITIVO"
    nome_tecnica: str
    tatica: str
    tatica_id: str
    severidade: str
    e_benigna: bool                         # True para benigna E falso positivo
    tipo: str                               # "ameaca" | "benigna" | "falso_positivo"
    motivo_fp: str = ""                     # por que esta linha poderia gerar FP
    tecnica_fp_alvo: str = ""              # técnica que o FP imita superficialmente
    ground_truth_tecnicas: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Banco de variações realistas
# ---------------------------------------------------------------------------
IPS_EXTERNOS = [
    "203.0.113.5", "198.51.100.7", "185.220.101.45", "91.108.4.12",
    "45.33.32.156", "162.247.74.201", "178.73.215.171", "104.244.74.11",
]
IPS_INTERNOS = [
    "10.0.0.1", "10.0.1.15", "192.168.1.100", "192.168.0.50",
    "172.16.0.23", "10.10.10.5",
]
USUARIOS = ["root", "admin", "user1", "jsmith", "deploy", "svc_backup", "operator"]
HOSTNAMES = ["web-01", "db-master", "jumphost", "corp-ws-12", "fileserver", "api-gw"]


# ---------------------------------------------------------------------------
# Linhas benignas por fonte (atividade rotineira sem indicadores suspeitos)
# ---------------------------------------------------------------------------
BENIGNAS_POR_FONTE: dict[str, list[str]] = {
    "linux_syslog": [
        "systemd[1]: Started NetworkManager.service.",
        "kernel: eth0: renamed from veth3a1b2c",
        "sshd[9201]: Accepted publickey for deploy from 10.0.0.5 port 48291 ssh2",
        "systemd[1]: Reloading.",
        "dhclient[812]: DHCPACK from 10.0.0.1 (xid=0x3c12a4f1)",
        "named[1034]: client 10.0.0.5#51432: query (cache) 'api.example.com/A/IN' NOERROR",
        "rsyslogd: exiting on signal 15 (SIGTERM).",
        "auditd[1001]: auditd startup succeeded",
        "kernel: usb 1-1: new high-speed USB device number 3 using xhci_hcd",
        "pam_unix(sudo:session): session opened for user root by deploy(uid=1001)",
    ],
    "windows_eventlog": [
        "Event ID 4624: An account was successfully logged on. Account Name: jsmith Logon Type: 3",
        "Event ID 7036: The Windows Update service entered the running state.",
        "Event ID 4634: An account was logged off. Account Name: deploy",
        "Event ID 4648: A logon was attempted using explicit credentials. Target: CORP\\svc_backup",
        "Event ID 1074: The process wuauclt.exe initiated the restart of computer for Windows Update.",
        "Event ID 4672: Special privileges assigned to new logon. Account Name: SYSTEM",
        "Event ID 5156: The Windows Filtering Platform permitted a connection. Application: svchost.exe",
    ],
    "macos_unified_log": [
        "com.apple.xpc.launchd[1] (com.apple.mdworker): Service only ran for 0 seconds",
        "kernel[0]: AppleIntelCPUPowerManagement: (built 10:00:00 Apr 1 2024)",
        "authd[350]: Succeeded authorizing right 'com.apple.trust-settings.admin'",
        "com.apple.security.pboxd[312]: SandboxViolation: mdworker(412) deny(1) file-read-data /private/etc/passwd",
        "kernel[0]: IOThunderboltSwitch: Tunnel opened successfully",
        "com.apple.TimeMachine[801]: Starting scheduled backup",
    ],
    "rede": [
        "ALLOW TCP 10.0.0.5:54231 -> 93.184.216.34:443 ESTABLISHED",
        "DHCPACK 10.0.1.15 via eth0",
        "DNS QUERY 10.0.0.5 -> 8.8.8.8 for api.github.com A NOERROR",
        "NTP SYNC 10.0.0.1 -> pool.ntp.org offset=+0.003s",
        "ALLOW TCP 192.168.1.100:60211 -> 140.82.121.4:443 len=60 TOS=0x00",
        "DNS RESPONSE api.github.com -> 140.82.121.4 TTL=60",
        "ALLOW UDP 10.0.0.1:68 -> 255.255.255.255:67 DHCP DISCOVER",
    ],
}


# ---------------------------------------------------------------------------
# Falsos positivos por fonte
# Cada entrada: (texto_log, motivo_fp, tecnica_mitre_que_imita)
# O "motivo_fp" explica por que parece suspeito mas não é.
# ---------------------------------------------------------------------------
FALSOS_POSITIVOS_POR_FONTE: dict[str, list[tuple[str, str, str]]] = {
    "linux_syslog": [
        (
            "deploy[4421]: gcc -o build/app src/main.c src/utils.c -O2 -Wall",
            "Uso de gcc em pipeline CI/CD legítimo (imita T1027.004 Compile After Delivery)",
            "T1027.004",
        ),
        (
            "backup[2201]: openssl enc -aes-256-cbc -in /var/backups/db.sql -out /mnt/nas/db.sql.enc -pass file:/etc/backup.key",
            "Criptografia de backup rotineiro com openssl (imita T1027 Obfuscated Files)",
            "T1027",
        ),
        (
            "deploy[5512]: base64 -d /tmp/deploy_token.b64 > /tmp/deploy_token",
            "Decodificação de token de deploy em pipeline CI/CD (imita T1027 via base64)",
            "T1027",
        ),
        (
            "sysadmin[3301]: systemctl list-units --type=service --state=running",
            "Admin verificando serviços para diagnóstico de lentidão (imita T1007 Service Discovery)",
            "T1007",
        ),
        (
            "monitor[9901]: tcpdump -i eth0 -c 100 -w /tmp/capture_$(date +%F).pcap port 443",
            "Captura de diagnóstico de rede pelo time de ops (imita T1040 Network Sniffing)",
            "T1040",
        ),
        (
            "jenkins[7712]: ssh-keygen -t ed25519 -C 'jenkins-deploy-key' -f /var/lib/jenkins/.ssh/deploy_ed25519 -N ''",
            "Geração de chave SSH para deploy automatizado em CI/CD (imita T1098.001)",
            "T1098.001",
        ),
        (
            "sre[4401]: nmap -sV -p 22,80,443,8080 10.0.0.0/24 -oN /tmp/infra_scan_$(date +%F).txt",
            "Scan de inventário de infraestrutura pelo time SRE (imita T1046 Network Service Scanning)",
            "T1046",
        ),
        (
            "cron[1001]: /usr/bin/python3 /opt/scripts/cleanup_logs.py --delete-older-than 30d",
            "Script de limpeza de logs agendado (imita T1070 Indicator Removal on Host)",
            "T1070",
        ),
    ],
    "windows_eventlog": [
        (
            "Event ID 4688: Process created: C:\\Program Files\\Git\\usr\\bin\\ssh.exe -T git@github.com",
            "Conexão SSH ao GitHub via Git para clone/push legítimo (imita T1021.004 SSH)",
            "T1021.004",
        ),
        (
            "Event ID 4688: Process created: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NonInteractive -Command \"[Convert]::ToBase64String([IO.File]::ReadAllBytes('C:\\deploy\\config.json'))\"",
            "Script de deploy convertendo config para base64 para transferência (imita T1027 via PowerShell)",
            "T1027",
        ),
        (
            "Event ID 4688: Process created: C:\\Windows\\System32\\sc.exe query type= all state= all",
            "Helpdesk verificando estado de serviços para suporte remoto (imita T1007 Service Discovery)",
            "T1007",
        ),
        (
            "Event ID 4732: A member was added to a security-enabled local group. Group: Administrators. Member: CORP\\svc_deploy",
            "Conta de serviço adicionada ao grupo Admins para janela de manutenção planejada (imita T1078)",
            "T1078",
        ),
        (
            "Event ID 4688: Process created: C:\\Windows\\System32\\reg.exe export HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run C:\\backup\\startup_keys.reg",
            "Export de chaves de registro para auditoria de compliance (imita T1012 Query Registry)",
            "T1012",
        ),
        (
            "Event ID 4688: Process created: C:\\Windows\\System32\\net.exe user /domain",
            "Helpdesk listando usuários do domínio para reset de senha (imita T1087 Account Discovery)",
            "T1087",
        ),
    ],
    "macos_unified_log": [
        (
            "bash[4412]: security find-generic-password -a deploy -s github-token -w",
            "Script de CI/CD recuperando token do Keychain legitimamente (imita T1555.001 Keychain)",
            "T1555.001",
        ),
        (
            "launchctl[2201]: load /Library/LaunchDaemons/com.company.monitoring.plist",
            "Instalação de agente de monitoramento corporativo via MDM (imita T1543.004 Launch Daemon)",
            "T1543.004",
        ),
        (
            "bash[3301]: curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh | bash",
            "Instalação do Homebrew em setup de novo Mac corporativo (imita T1059.004 Unix Shell)",
            "T1059.004",
        ),
        (
            "osascript[5512]: tell application \"System Events\" to get name of every process",
            "Script de automação AppleScript para inventário de TI (imita T1057 Process Discovery)",
            "T1057",
        ),
    ],
    "rede": [
        (
            "2026-01-15T09:14:22Z ALLOW TCP 10.0.0.50:55234 -> 203.0.113.5:443 len=1420 flags=PA TLS SNI=api.vendor.com",
            "Tráfego HTTPS legítimo para API de fornecedor parceiro (imita C2 em T1071.001)",
            "T1071.001",
        ),
        (
            "2026-01-15T09:22:11Z ALLOW TCP 10.0.0.5:60100 -> 185.220.101.45:22 len=240 SSH",
            "Desenvolvedor acessando servidor de staging via SSH (IP parece Tor mas é DC legítimo)",
            "T1021.004",
        ),
        (
            "2026-01-15T10:01:00Z DNS QUERY 10.0.0.10 -> 8.8.8.8 for dc1.corp.internal TXT NXDOMAIN",
            "Resolução DNS interna falhando por misconfiguration de split-DNS (imita DNS tunneling T1071.004)",
            "T1071.004",
        ),
        (
            "2026-01-15T10:15:33Z ALLOW ICMP 10.0.0.20 -> 10.0.1.0/24 type=8 (echo-request) seq=1-254",
            "Script de descoberta de hosts pelo time de infra para inventário (imita T1018 Remote System Discovery)",
            "T1018",
        ),
        (
            "2026-01-15T11:30:00Z ALLOW TCP 10.0.0.30:54001 -> 10.0.0.5:445 SMB len=200",
            "Backup via SMB para servidor de arquivos corporativo (imita T1021.002 SMB/Windows Admin Shares)",
            "T1021.002",
        ),
    ],
}


# ---------------------------------------------------------------------------
# Formatadores de timestamp por fonte
# ---------------------------------------------------------------------------
def _ts_linux(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S").replace(" 0", "  ")

def _ts_windows(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")

def _ts_macos(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def _ts_rede(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

PREFIXOS_POR_FONTE = {
    "linux_syslog":      lambda dt, h: f"{_ts_linux(dt)} {h} ",
    "windows_eventlog":  lambda dt, h: f"{_ts_windows(dt)} [{h}] ",
    "macos_unified_log": lambda dt, h: f"{_ts_macos(dt)} {h} ",
    "rede":              lambda dt, h: f"{_ts_rede(dt)} [{h}] ",
}


# ---------------------------------------------------------------------------
# Variações de linha (IPs, PIDs, usuários)
# ---------------------------------------------------------------------------
def _variar_linha(linha: str) -> str:
    for ip in IPS_EXTERNOS:
        if ip in linha:
            linha = linha.replace(ip, random.choice(IPS_EXTERNOS), 1)
    for ip in IPS_INTERNOS:
        if ip in linha:
            linha = linha.replace(ip, random.choice(IPS_INTERNOS), 1)
    linha = re.sub(r'\b5\d{4}\b', str(random.randint(49152, 65535)), linha, count=1)
    linha = re.sub(r'\[(\d{4,6})\]', lambda m: f"[{random.randint(1000, 99999)}]", linha, count=1)
    for u in USUARIOS:
        if u in linha:
            linha = linha.replace(u, random.choice(USUARIOS), 1)
            break
    return linha


def _adicionar_prefixo(linha: str, fonte: str, dt: datetime) -> str:
    hostname = random.choice(HOSTNAMES)
    prefixo = PREFIXOS_POR_FONTE.get(fonte, lambda d, h: "")(dt, hostname)
    if re.match(r"^\d{4}-\d{2}-\d{2}", linha) or re.match(r"^[A-Z][a-z]{2}\s", linha):
        return linha
    return prefixo + linha


# ---------------------------------------------------------------------------
# Coletor de padrões dos JSONs
# ---------------------------------------------------------------------------
def carregar_padroes(arquivos: list[str]) -> dict[str, list[dict]]:
    por_fonte: dict[str, list[dict]] = {f: [] for f in FONTES_SUPORTADAS}

    for arquivo in arquivos:
        path = Path(arquivo)
        if not path.exists():
            print(f"[!] Arquivo não encontrado: {arquivo}")
            continue

        data = json.loads(path.read_text(encoding="utf-8"))
        tatica    = data.get("tatica", "")
        tatica_id = data.get("tatica_id", "")

        for padrao in data.get("padroes", []):
            tecnica_id   = padrao["tecnica_id"]
            nome_tecnica = padrao["nome_tecnica"]
            severidade   = padrao.get("severidade_sugerida", "medium")

            for padrao_log in padrao.get("padroes_log", []):
                fonte = padrao_log.get("fonte", "")
                if fonte not in FONTES_SUPORTADAS:
                    continue
                exemplos = [
                    ex for ex in padrao_log.get("exemplos", [])
                    if ex
                    and "não aplicável" not in ex.lower()
                    and "nao aplicavel" not in ex.lower()
                    and len(ex.strip()) > 10
                ]
                if not exemplos:
                    continue

                por_fonte[fonte].append({
                    "tecnica_id":   tecnica_id,
                    "nome_tecnica": nome_tecnica,
                    "tatica":       tatica,
                    "tatica_id":    tatica_id,
                    "severidade":   severidade,
                    "exemplos":     exemplos,
                    "fonte":        fonte,
                })

    return por_fonte


# ---------------------------------------------------------------------------
# Gerador principal
# ---------------------------------------------------------------------------
class GeradorLogsSinteticos:
    """
    Gera arquivos .log realistas com três classes de linhas intercaladas:
      - ameaca        (ratio_ameacas)
      - benigna       (ratio_benignas)
      - falso_positivo (ratio_fp)
    """

    def __init__(
        self,
        padroes_por_fonte: dict[str, list[dict]],
        linhas_por_fonte: int = 200,
        ratio_benignas: float = RATIO_BENIGNAS,
        ratio_fp: float = RATIO_FALSOS_POS,
        seed: int = SEED,
    ):
        total = ratio_benignas + ratio_fp
        if total >= 1.0:
            raise ValueError(f"ratio_benignas + ratio_fp deve ser < 1.0, recebido {total:.2f}")
        self.padroes       = padroes_por_fonte
        self.linhas        = linhas_por_fonte
        self.ratio_benignas = ratio_benignas
        self.ratio_fp      = ratio_fp
        random.seed(seed)

    def gerar_todos(self, diretorio_saida: Path) -> dict[str, Path]:
        """Gera um .log + -metadata.json por fonte."""
        diretorio_saida.mkdir(parents=True, exist_ok=True)
        arquivos = {}

        for fonte in FONTES_SUPORTADAS:
            padroes = self.padroes.get(fonte, [])
            if not padroes:
                print(f"[!] Sem padrões para: {fonte}")
                continue
            entradas, path_log, _ = self._gerar_fonte(fonte, padroes, diretorio_saida)
            arquivos[fonte] = path_log

            n_ameaca = sum(1 for e in entradas if e.tipo == "ameaca")
            n_ben    = sum(1 for e in entradas if e.tipo == "benigna")
            n_fp     = sum(1 for e in entradas if e.tipo == "falso_positivo")
            print(
                f"[+] {fonte}: {len(entradas)} linhas "
                f"(ameaças={n_ameaca}, benignas={n_ben}, falsos_pos={n_fp}) "
                f"→ {path_log.name}"
            )

        return arquivos

    def _gerar_fonte(
        self, fonte: str, padroes: list[dict], diretorio_saida: Path
    ) -> tuple[list[EntradaLog], Path, Path]:

        dt_base = datetime(2026, 1, 15, 8, 0, 0)

        n_fp      = int(self.linhas * self.ratio_fp)
        n_benignas = int(self.linhas * self.ratio_benignas)
        n_ameacas = self.linhas - n_fp - n_benignas

        # --- slots de ameaça ---
        slots_ameaca = []
        for i in range(n_ameacas):
            p = padroes[i % len(padroes)]
            slots_ameaca.append(("ameaca", p, _variar_linha(random.choice(p["exemplos"]))))

        # --- slots de falso positivo ---
        fps_disponiveis = FALSOS_POSITIVOS_POR_FONTE.get(fonte, [])
        slots_fp = []
        if fps_disponiveis:
            for i in range(n_fp):
                texto_fp, motivo, tecnica_alvo = fps_disponiveis[i % len(fps_disponiveis)]
                slots_fp.append(("falso_positivo", texto_fp, motivo, tecnica_alvo))
        else:
            # Fallback: usa benignas extras se não há FPs para esta fonte
            n_benignas += n_fp

        # --- agenda intercalada ---
        agenda: list = (
            slots_ameaca +
            slots_fp +
            [("benigna", None, None, None)] * n_benignas
        )
        random.shuffle(agenda)

        entradas: list[EntradaLog] = []
        for num_linha, item in enumerate(agenda, start=1):
            dt = dt_base + timedelta(seconds=num_linha * random.randint(1, 30))
            tipo = item[0]

            if tipo == "ameaca":
                _, padrao, texto = item
                texto_final = _adicionar_prefixo(texto, fonte, dt)
                e = EntradaLog(
                    linha_numero=num_linha,
                    linha_texto=texto_final,
                    fonte=fonte,
                    tecnica_id=padrao["tecnica_id"],
                    nome_tecnica=padrao["nome_tecnica"],
                    tatica=padrao["tatica"],
                    tatica_id=padrao["tatica_id"],
                    severidade=padrao["severidade"],
                    e_benigna=False,
                    tipo="ameaca",
                    ground_truth_tecnicas=[padrao["tecnica_id"]],
                )

            elif tipo == "falso_positivo":
                _, texto_fp, motivo, tecnica_alvo = item
                texto_final = _adicionar_prefixo(_variar_linha(texto_fp), fonte, dt)
                e = EntradaLog(
                    linha_numero=num_linha,
                    linha_texto=texto_final,
                    fonte=fonte,
                    tecnica_id="FALSO_POSITIVO",
                    nome_tecnica="Atividade Legítima Superficialmente Suspeita",
                    tatica="",
                    tatica_id="",
                    severidade="info",
                    e_benigna=True,
                    tipo="falso_positivo",
                    motivo_fp=motivo,
                    tecnica_fp_alvo=tecnica_alvo,
                    ground_truth_tecnicas=[],
                )

            else:  # benigna
                opcoes = BENIGNAS_POR_FONTE.get(fonte, ["[benign log entry]"])
                texto_final = _adicionar_prefixo(random.choice(opcoes), fonte, dt)
                e = EntradaLog(
                    linha_numero=num_linha,
                    linha_texto=texto_final,
                    fonte=fonte,
                    tecnica_id="BENIGNO",
                    nome_tecnica="Atividade Normal",
                    tatica="",
                    tatica_id="",
                    severidade="info",
                    e_benigna=True,
                    tipo="benigna",
                    ground_truth_tecnicas=[],
                )

            entradas.append(e)

        # Escreve .log
        nome_base = fonte.replace("_", "-")
        path_log  = diretorio_saida / f"{nome_base}.log"
        path_log.write_text(
            "\n".join(e.linha_texto for e in entradas) + "\n",
            encoding="utf-8",
        )

        # Escreve -metadata.json
        path_meta = diretorio_saida / f"{nome_base}-metadata.json"
        path_meta.write_text(
            json.dumps([asdict(e) for e in entradas], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        return entradas, path_log, path_meta


# ---------------------------------------------------------------------------
# CLI / main
# ---------------------------------------------------------------------------
def main(
    linhas_por_fonte: int = 200,
    diretorio_saida: Path = DIRETORIO_SAIDA_PADRAO,
    ratio_fp: float = RATIO_FALSOS_POS,
    ratio_benignas: float = RATIO_BENIGNAS,
    json_dir: Optional[Path] = None,
) -> dict[str, Path]:
    print("=" * 60)
    print("Gerador de Logs Sintéticos — Dataset MITRE ATT&CK")
    print("=" * 60)
    print(f"  Saída          : {diretorio_saida.resolve()}")
    print(f"  Linhas/fonte   : {linhas_por_fonte}")
    print(f"  Ratio ameaças  : {1 - ratio_benignas - ratio_fp:.0%}")
    print(f"  Ratio benignas : {ratio_benignas:.0%}")
    print(f"  Ratio falsos+  : {ratio_fp:.0%}")
    print()

    data_dir = json_dir or MITRE_DATA_DIR_PADRAO
    jsons = _resolver_arquivos_json(data_dir)
    padroes = carregar_padroes(jsons)
    for fonte, lista in padroes.items():
        print(f"  {fonte}: {len(lista)} padrões com exemplos reais")
    print()

    gerador = GeradorLogsSinteticos(
        padroes,
        linhas_por_fonte=linhas_por_fonte,
        ratio_benignas=ratio_benignas,
        ratio_fp=ratio_fp,
    )
    arquivos = gerador.gerar_todos(diretorio_saida)

    print(f"\n[✓] Logs gerados em: {diretorio_saida.resolve()}")
    return arquivos


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Gera logs sintéticos com ameaças, benignas e falsos positivos."
    )
    parser.add_argument(
        "--saida", type=Path, default=DIRETORIO_SAIDA_PADRAO,
        help=f"Diretório de saída (padrão: {DIRETORIO_SAIDA_PADRAO})"
    )
    parser.add_argument(
        "--linhas", type=int, default=200,
        help="Linhas por arquivo de log (padrão: 200)"
    )
    parser.add_argument(
        "--ratio-fp", type=float, default=RATIO_FALSOS_POS,
        help=f"Proporção de falsos positivos (padrão: {RATIO_FALSOS_POS})"
    )
    parser.add_argument(
        "--ratio-benignas", type=float, default=RATIO_BENIGNAS,
        help=f"Proporção de linhas benignas (padrão: {RATIO_BENIGNAS})"
    )
    parser.add_argument(
        "--json-dir", type=Path, default=None,
        help="Diretório com os JSONs do dataset MITRE (padrão: ./data ou $MITRE_DATA_DIR)"
    )
    args = parser.parse_args()

    main(
        linhas_por_fonte=args.linhas,
        diretorio_saida=args.saida,
        ratio_fp=args.ratio_fp,
        ratio_benignas=args.ratio_benignas,
        json_dir=args.json_dir,
    )