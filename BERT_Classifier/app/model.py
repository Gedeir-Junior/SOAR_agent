from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import torch.nn.functional as F
from pathlib import Path
import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "bert-model-4"

class BertPhishingModel:
    def __init__(self, temperature=1.5, mc_samples=10):
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
        self.model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
        
        # 1. Redimensionamento padrão (ajusta o tamanho da matriz)
        self.model.resize_token_embeddings(len(self.tokenizer)) 
        
        # 2. Lógica Manual de Stanford (Média de Embeddings)
        # Isso evita o erro 500 e melhora a calibração para o score 0.5
        self._apply_mean_resizing()
        
        self.temperature = temperature
        self.mc_samples = mc_samples
        self.model.eval()

    def _apply_mean_resizing(self):
        """ Inicializa novos tokens com a média dos antigos para evitar saturação """
        weights = self.model.get_input_embeddings().weight
        with torch.no_grad():
            # Calcula a média dos embeddings existentes (excluindo os novos no final)
            old_vocab_size = 30522 # Tamanho padrão do BERT base
            if weights.shape[0] > old_vocab_size:
                mean_embedding = weights[:old_vocab_size].mean(dim=0)
                # Atribui a média para os novos tokens (do 30522 até o final)
                weights[old_vocab_size:] = mean_embedding

    def enable_dropout(self):
        """ Força as camadas de dropout a ficarem ativas mesmo em modo eval() """
        for module in self.model.modules():
            if module.__class__.__name__.startswith('Dropout'):
                module.train()

    def predict(self, text: str):
        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            padding="max_length",
            max_length=512
        )

        all_probs = []

        # Ativa o comportamento não-determinístico
        self.enable_dropout()

        with torch.no_grad():
            for _ in range(self.mc_samples):
                outputs = self.model(**inputs)
                logits = outputs.logits
                
                # 1. Aplicação de Temperature Scaling
                # Suaviza os logits antes do softmax para calibrar a confiança
                scaled_logits = logits / self.temperature
                
                probs = F.softmax(scaled_logits, dim=1)
                all_probs.append(probs)

        # 2. Agregação Monte Carlo
        # Tiramos a média das probabilidades de todas as passagens
        stacked_probs = torch.stack(all_probs)
        avg_probs = torch.mean(stacked_probs, dim=0)
        
        # Cálculo de incerteza (variância entre as predições)
        variance = torch.var(stacked_probs, dim=0).mean().item()

        label_id = torch.argmax(avg_probs, dim=1).item()
        confidence = avg_probs[0][label_id].item()

        label = "phishing" if label_id == 1 else "legitimate"

        return {
            "bert": {
                "label": label,
                "confidence": round(confidence, 4),
                "uncertainty_score": round(variance, 6) # Nova métrica para o relatório
            }
        }

model = BertPhishingModel(temperature=1.5, mc_samples=10)