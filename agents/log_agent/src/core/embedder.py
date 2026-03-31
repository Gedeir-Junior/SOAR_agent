from sentence_transformers import SentenceTransformer

class LogEmbedder:
    def __init__(self, model_name='all-MiniLM-L6-v2'):
        self.model = SentenceTransformer(model_name)

    def get_vector(self, text):
        return self.model.encode(text).tolist()