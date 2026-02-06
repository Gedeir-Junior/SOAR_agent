from pydantic import BaseModel

class EmailInput(BaseModel):
    sender: str
    subject: str
    receiver: str
    body: str
    links: str

class ClassificationResponse(BaseModel):
    bert: dict
