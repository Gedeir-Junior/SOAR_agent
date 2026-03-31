import torch
import torch.nn as nn

class LSTMAutoencoder(nn.Module):
    def __init__(self, input_dim=384, hidden_dim=64, seq_len=10):
        super(LSTMAutoencoder, self).__init__()
        self.seq_len = seq_len
        
        # Encoder: Comprime a sequência de logs
        self.encoder = nn.LSTM(input_dim, hidden_dim, batch_first=True)
        
        # Decoder: Tenta reconstruir a sequência original
        self.decoder = nn.LSTM(hidden_dim, input_dim, batch_first=True)
        self.output_layer = nn.Linear(input_dim, input_dim)

    def forward(self, x):
        # x shape: (batch, seq_len, input_dim)
        _, (hidden, _) = self.encoder(x)
        
        # Repete o estado oculto para o decoder reconstruir todos os passos
        decoder_input = hidden.repeat(self.seq_len, 1, 1).transpose(0, 1)
        x_prime, _ = self.decoder(decoder_input)
        
        return self.output_layer(x_prime)

def get_anomaly_score(original, reconstructed):
    mse = nn.MSELoss()
    return mse(original, reconstructed).item()