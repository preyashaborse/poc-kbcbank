from pydantic import BaseModel


class CreateRiskRequest(BaseModel):
    title: str
    description: str
    category: list[str]


class AnalyzePolicyImpactRequest(BaseModel):
    risk_id: int
    risk_title: str
    risk_description: str


class PolicyGapAnalysisRequest(BaseModel):
    risk_id: int
    risk_title: str
    risk_description: str
    policy_name: str
