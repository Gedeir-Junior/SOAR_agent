from sentence_transformers import SentenceTransformer

class LogEmbedder:
    def __init__(self, model_name='all-MiniLM-L6-v2'):
        self.model = SentenceTransformer(model_name)

    def get_embedding(self, cleaned_log):
        embedding = self.model.encode(cleaned_log)
        return embedding.tolist()