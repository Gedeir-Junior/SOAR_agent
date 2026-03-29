import torch
import torch.nn as nn

class LSTMAutoencoder(nn.Module):
    def __init__(self, input_dim, hidden_dim, sequence_length):
        super(LSTMAutoencoder, self).__init__()
        self.sequence_length = sequence_length
        
        # --- ENCODER ---
        # Comprime a sequência de logs em um vetor de contexto "oculto"
        self.encoder = nn.LSTM(input_dim, hidden_dim, batch_first=True)
        
        # --- DECODER ---
        # Tenta reconstruir a sequência original a partir do resumo do encoder
        self.decoder = nn.LSTM(hidden_dim, input_dim, batch_first=True)
        
        # Camada final para ajustar a dimensão de saída à de entrada
        self.output_layer = nn.Linear(input_dim, input_dim)

    def forward(self, x):
        # x shape: (batch, sequence_length, input_dim)
        
        # Passa pelo Encoder
        _, (hidden, _) = self.encoder(x)
        # hidden shape: (1, batch, hidden_dim)
        
        # Prepara a entrada do Decoder repetindo o estado oculto
        # Queremos que o decoder tente recriar cada passo da sequência
        decoder_input = hidden.repeat(self.sequence_length, 1, 1).transpose(0, 1)
        
        # Passa pelo Decoder
        x_prime, _ = self.decoder(decoder_input)
        
        # Ajuste final de dimensão
        return self.output_layer(x_prime)

def calculate_anomaly_score(original, reconstructed):
    """
    Calcula o Erro Quadrático Médio (MSE). 
    Quanto maior o erro, mais anômalo é o comportamento.
    """
    mse = nn.MSELoss()
    return mse(original, reconstructed).item()