from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class RiskResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str
    category: list[str]
    createdAt: datetime = Field(description="Read-only, set by the database")


class CreateRiskResponse(BaseModel):
    success: bool
    risk: RiskResponse
