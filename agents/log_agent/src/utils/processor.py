import re

class LogProcessor:
    def __init__(self):
        # Padrões para anonimizar mas manter a estrutura
        self.filters = [
            (r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+Z', '<TIMESTAMP>'),
            (r'\[\d+\]', '[<PID>]'),
            (r'\d+\.\d+\.\d+\.\d+', '<IP>'),
            (r'uid=(\d+)', 'uid=<UID>'),
            (r'0x[a-fA-F0-9]+', '<HEX>')
        ]

    def process(self, log_line):
        """Retorna (texto_limpo, metadados_extraidos)"""
        # Extração simples de metadados antes de limpar
        metadata = {
            "is_root": "root" in log_line.lower() or "uid=0" in log_line,
            "has_sudo": "sudo" in log_line.lower(),
            "raw": log_line
        }

        cleaned = log_line
        for pattern, replacement in self.filters:
            cleaned = re.sub(pattern, replacement, cleaned)
            
        return cleaned.strip(), metadata