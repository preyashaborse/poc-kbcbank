from pydantic import BaseModel, ConfigDict, Field


class CreateRiskRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    title: str
    description: str
    category: list[str]
    level: str
    type: str
    areas_of_impact: list[str] = Field(alias="areasOfImpact")
    owner_organization: str = Field(alias="ownerOrganization")


class AnalyzePolicyImpactRequest(BaseModel):
    risk_id: str
    risk_title: str
    risk_description: str


class PolicyGapAnalysisRequest(BaseModel):
    risk_id: str
    risk_title: str
    risk_description: str
    policy_name: str
