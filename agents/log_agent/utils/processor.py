import re

class LogProcessor:
    def __init__(self):
        self.filters = [
            (r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d+Z', '<TIMESTAMP>'),
            (r'\[(\d+)\]', '[<PID>]'), # Capturamos o dígito aqui
            (r'\d+\.\d+\.\d+\.\d+', '<IP>'),
            (r'uid=(\d+)', 'uid=<UID>') # Adicionado para capturar privilégio
        ]

    def process(self, log_line):
        # Extração de metadados antes da limpeza pesada
        metadata = {
            "is_root": 1 if "uid=0" in log_line or "root" in log_line.lower() else 0,
            "has_sudo": 1 if "sudo" in log_line.lower() else 0
        }
        
        cleaned = log_line
        for pattern, replacement in self.filters:
            cleaned = re.sub(pattern, replacement, cleaned)
            
        return cleaned.strip(), metadata