from pydantic import BaseModel


class CreateRiskRequest(BaseModel):
    name: str
    description: str
    category: list[str]
