from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Dataclass de saída
# ---------------------------------------------------------------------------
@dataclass
class LogFiltrado:
    """Log após filtragem e classificação de plataforma"""
    numero_linha: int
    linha_original: str
    plataforma: str              # linux | windows | macos | network | desconhecida
    foi_filtrado: bool           # True se foi removido por padrão inofensivo
    motivo_filtro: str = ""      # Razão pela qual foi filtrado
    tags_plataforma: list[str] = None  # Tags para otimizar buscas


# ---------------------------------------------------------------------------
# Padrões de Comandos Inofensivos (não representam ameaça)
# ---------------------------------------------------------------------------

COMANDOS_INOFENSIVOS = {
    # Atualizações e gerenciamento de pacotes
    r"(?:COMMAND=\S*/)?(apt|apt-get|dnf|yum|pacman|brew|port|pkg)\s+(update|upgrade|install|remove|autoremove)",
    r"(apt|yum|dnf)\s+clean\s+(all|cache|packages)",
    r"pacman\s+-S\w*u",  # pacman update
    
    # Limpeza de sistema
    r"(rm|rm -rf)\s+/tmp",
    r"(clear|cls|reset)\s*$",
    r"journalctl\s+--vacuum",
    r"tmp\s*cleanup",
    
    # Operações normais de log
    r"logrotate",
    r"rsyslog|syslog-ng",
    r"(tail|head|less|more|cat)\s+/var/log",
    
    # Sincronização e backup
    r"rsync\s+.*--delete",
    r"ntp|ntpd|chronyd",
    r"(backup|restore)\s+(started|completed|finished)",
    
    # Verificações de saúde normais
    r"healthcheck|health_check",
    r"monitoring|monitored",
    r"heartbeat|ping.*pong",
    r"service\s+(started|stopped|restarted)",
    
    # Eventos de negação/bloqueio de segurança (sistema REPELINDO o ataque, não sofrendo)
    # AppArmor "denied", SELinux "denied/avc", firewall bloqueando — são alertas do defensor,
    # não evidências de técnica MITRE bem-sucedida.
    r"apparmor.*denied|apparmor.*DENIED",
    r"USER_AVC.*denied|avc:\s+denied",
    r"selinux.*denied|type=AVC.*denied",
    r"(ufw|iptables|firewalld|nftables).*(BLOCK|DROP|REJECT|denied)",
    r"pam_unix.*authentication failure",   # autenticação FALHOU (não é intrusão bem-sucedida)
    r"Failed password for",                # tentativa de login REJEITADA
    r"Invalid user.*from",                 # login inválido rejeitado
    r"Connection (refused|reset|closed)",  # conexão RECUSADA pelo sistema

    # Cron e jobs agendados
    r"CRON\[",
    r"cron:|scheduled task",
    r"anacron|at\s+",
    
    # DHCP, DNS, roteamento normais
    r"DHCPACK|DHCPDISCOVER|DHCPOFFER",
    r"DHCP\s+lease|dhclient",
    r"named\[.*\]:\s+(query|response|NOERROR)",
    r"dnsmasq.*query",
    
    # Rotinas de conectividade
    r"(eth|en|wlan|wifi|docker|veth)\d+\s+(UP|DOWN|RUNNING)",
    r"link-local",
    r"neighbor\s+(added|deleted)",
    r"inet.*broadcast",
}

PADROES_INOFENSIVOS_COMPILADOS = [re.compile(padrao, re.IGNORECASE) for padrao in COMANDOS_INOFENSIVOS]


# ---------------------------------------------------------------------------
# Detecção de Plataforma
# ---------------------------------------------------------------------------

INDICADORES_PLATAFORMA = {
    "linux": {
        "keywords": [
            r"kernel\[",
            r"systemd\[",
            r"sshd\[",
            r"sudo:",
            r"/var/log/(syslog|messages)",
            r"cron\[",
            r"audit:",
            r"selinux",
            r"apparmor",
            r"(eth|en|wlan|docker)\d+",
            r"journalctl",
            r"dmesg",
        ],
        "tags": ["linux", "syslog", "unix"],
    },
    "windows": {
        "keywords": [
            r"Event ID",
            r"EventLog|Event Type",
            r"Source:\s+(System|Security|Application)",
            r"\\Device\\",
            r"C:\\Windows",
            r"Registry",
            r"WMI",
            r"Audit",
            r"PowerShell",
            r"Security Log",
            r"SAM|LSA|NTLM",
        ],
        "tags": ["windows", "eventlog", "wineventlog"],
    },
    "macos": {
        "keywords": [
            r"kernel\[",
            r"launchd\[",
            r"/var/log/system\.log",
            r"/var/log/auth\.log",
            r"OSLog",
            r"security\[",
            r"kernel:.*IOKit|kernel:.*BSD",
            r"com\.apple",
            r"launchctl",
        ],
        "tags": ["macos", "darwin", "osx"],
    },
    "network": {
        "keywords": [
            r"(firewall|iptables|pf|ufw)",
            r"(tcp|udp)\s+\d+\.\d+\.\d+\.\d+",
            r"SRC=|DST=",  # iptables logging
            r"(allowed|denied|blocked)\s+(from|to)",
            r"connection\s+(established|terminated|refused)",
            r"port\s+\d+",
            r"(ssh|ftp|http|https|dns|ntp)",
            r"DROP|REJECT|ACCEPT",
        ],
        "tags": ["network", "firewall", "traffic"],
    },
}


# ---------------------------------------------------------------------------
# Agente Filtrador
# ---------------------------------------------------------------------------

class AgenteFiltadorLogs:
    """
    Primeiro estágio do pipeline: filtra logs inofensivos e
    identifica a plataforma para buscas posteriores mais precisas.
    """

    def __init__(self, remover_inofensivos: bool = True):
        """
        Args:
            remover_inofensivos: se True, remove logs com comandos inofensivos
        """
        self.remover_inofensivos = remover_inofensivos

    def filtrar_arquivo(self, caminho_log: Path) -> tuple[list[LogFiltrado], str]:
        """
        Lê arquivo de log, filtra e detecta plataforma.
        
        Retorna: (lista de LogFiltrado, plataforma_detectada)
        """
        if not caminho_log.exists():
            raise FileNotFoundError(f"Arquivo de log não encontrado: {caminho_log}")

        with caminho_log.open(encoding="utf-8", errors="replace") as f:
            linhas_brutas = [l.rstrip("\n") for l in f.readlines()]

        linhas_indexadas = [
            (i + 1, linha)
            for i, linha in enumerate(linhas_brutas)
            if linha.strip()
        ]

        print(f"[*] Filtrador: {len(linhas_indexadas)} linhas úteis")

        # Detecta plataforma da primeira meia parte do arquivo
        plataforma = self._detectar_plataforma(linhas_indexadas[:len(linhas_indexadas)//2])
        print(f"[*] Plataforma detectada: {plataforma}")

        # Filtra logs
        resultados = self._filtrar_linhas(linhas_indexadas, plataforma)
        linhas_removidas = sum(1 for r in resultados if r.foi_filtrado)
        linhas_mantidas = sum(1 for r in resultados if not r.foi_filtrado)

        print(f"[*] Logs mantidos: {linhas_mantidas} | Removidos: {linhas_removidas}")

        return resultados, plataforma

    def filtrar_texto(self, texto: str) -> tuple[list[LogFiltrado], str]:
        """Filtra um bloco de texto de logs diretamente"""
        linhas = [(i + 1, l) for i, l in enumerate(texto.splitlines()) if l.strip()]
        plataforma = self._detectar_plataforma(linhas[:len(linhas)//2])
        return self._filtrar_linhas(linhas, plataforma), plataforma

    # ------------------------------------------------------------------
    # Detecção de Plataforma
    # ------------------------------------------------------------------
    def _detectar_plataforma(self, linhas: list[tuple[int, str]]) -> str:
        """Detecta a plataforma a partir de uma amostra de linhas"""
        texto_amostra = "\n".join(linha for _, linha in linhas)
        pontuacoes = {}

        for plataforma, config in INDICADORES_PLATAFORMA.items():
            pontuacoes[plataforma] = 0
            for regex in config["keywords"]:
                matches = len(re.findall(regex, texto_amostra, re.IGNORECASE))
                pontuacoes[plataforma] += matches

        # Retorna plataforma com maior pontuação
        plataforma_detectada = max(pontuacoes, key=pontuacoes.get)
        
        if pontuacoes[plataforma_detectada] == 0:
            plataforma_detectada = "desconhecida"

        return plataforma_detectada

    # ------------------------------------------------------------------
    # Filtragem de Linhas
    # ------------------------------------------------------------------
    def _filtrar_linhas(self, linhas_indexadas: list[tuple[int, str]], plataforma: str) -> list[LogFiltrado]:
        """Filtra logs inofensivos e adiciona metadados de plataforma"""
        resultados = []
        tags_plataforma = INDICADORES_PLATAFORMA.get(plataforma, {}).get("tags", ["desconhecida"])

        for numero_linha, linha in linhas_indexadas:
            foi_filtrado = False
            motivo_filtro = ""

            # Verifica se é inofensivo
            if self.remover_inofensivos:
                for padrao in PADROES_INOFENSIVOS_COMPILADOS:
                    if padrao.search(linha):
                        foi_filtrado = True
                        motivo_filtro = f"Comando inofensivo detectado: {padrao.pattern[:50]}"
                        break

            resultados.append(
                LogFiltrado(
                    numero_linha=numero_linha,
                    linha_original=linha,
                    plataforma=plataforma,
                    foi_filtrado=foi_filtrado,
                    motivo_filtro=motivo_filtro,
                    tags_plataforma=tags_plataforma.copy(),
                )
            )

        return resultados

    # ------------------------------------------------------------------
    # Obter logs não filtrados
    # ------------------------------------------------------------------
    def obter_logs_relevantes(self, logs_filtrados: list[LogFiltrado]) -> list[LogFiltrado]:
        """Retorna apenas logs que NÃO foram filtrados (logs relevantes)"""
        return [log for log in logs_filtrados if not log.foi_filtrado]