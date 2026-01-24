from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "bert-model"

class BertPhishingModel:
    def __init__(self):
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
        self.model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
        self.model.eval()

    def predict(self, text: str):
        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            padding=True,
            max_length=512
        )

        with torch.no_grad():
            outputs = self.model(**inputs)
            probs = torch.softmax(outputs.logits, dim=1)

        label_id = torch.argmax(probs, dim=1).item()
        confidence = probs[0][label_id].item()

        label = "phishing" if label_id == 1 else "legitimate"

        return {
            "bert": {
            "label": label,
            "confidence": round(confidence, 4)
        }
}


model = BertPhishingModel()
