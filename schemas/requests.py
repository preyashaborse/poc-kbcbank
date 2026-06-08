from pydantic import BaseModel


class CreateRiskRequest(BaseModel):
    title: str
    description: str
    category: list[str]
