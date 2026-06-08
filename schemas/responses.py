from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class RiskResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: int
    title: str = Field(validation_alias="name")
    description: str
    category: list[str]
    createdAt: datetime = Field(description="Read-only, set by the database")


class CreateRiskResponse(BaseModel):
    success: bool
    risk: RiskResponse


class DismissNotificationResponse(BaseModel):
    success: bool
