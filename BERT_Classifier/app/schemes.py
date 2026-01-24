from pydantic import BaseModel

class EmailInput(BaseModel):
    subject: str
    body: str

class ClassificationResponse(BaseModel):
    label: int
    probabilities: list[float]
