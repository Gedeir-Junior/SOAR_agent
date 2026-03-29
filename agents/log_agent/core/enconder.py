import torch

class LogSequenceEncoder:
    def __init__(self, model, embedder):
        self.model = model
        self.embedder = embedder
        self.model.eval()

    def get_context_vector(self, sequence_of_logs):
        """
        Transforma uma sequência de logs no 'pensamento' do modelo (espaço latente).
        Esse vetor é muito mais potente que um embedding isolado.
        """
        # sequence_of_logs: lista de strings limpas
        embeddings = [self.embedder.get_embedding(log) for log in sequence_of_logs]
        input_tensor = torch.FloatTensor([embeddings]) # (1, SEQ_LEN, INPUT_DIM)
        
        with torch.no_grad():
            # Passamos pelo encoder do nosso LSTMAutoencoder
            _, (hidden, _) = self.model.encoder(input_tensor)
            
        # Retorna o estado oculto (o resumo da sequência)
        return hidden.squeeze().tolist()