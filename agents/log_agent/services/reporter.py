from services.qdrant_client import QdrantLogConnector

class SOCReporter:
    def __init__(self, qdrant_client: QdrantLogConnector):
        self.qdrant = qdrant_client

    def generate_incident_report(self, anomaly_vector, raw_log):
        # 1. Busca contexto no Qdrant (Logs similares ou recentes)
        context_logs = self.qdrant.get_context_for_rag(anomaly_vector, limit=5)
        
        # 2. Monta o Prompt para o LLM (Exemplo conceitual)
        prompt = f"""
        Analise o seguinte incidente de segurança para um SOC Nível 1:
        Log Suspeito: {raw_log}
        
        Contexto de logs relacionados encontrados:
        {chr(10).join(context_logs)}
        
        Tarefa: Resuma a ameaça (ex: Brute Force, Escalada de Privilégio) 
        e sugira uma ação imediata.
        """
        
        # Aqui você chamaria a API do seu LLM de preferência
        # report = llm.query(prompt)
        return prompt # Por enquanto retorna o prompt para teste