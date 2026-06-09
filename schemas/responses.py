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


class PolicyImpact(BaseModel):
    policy_name: str
    rationale: str
    score: float = Field(ge=0, le=100, description="Impact score from 0-100%")


class AnalyzePolicyImpactResponse(BaseModel):
    success: bool
    risk_id: int
    risk_title: str
    impacted_policies: list[PolicyImpact]


class SectionGapAnalysis(BaseModel):
    section_number: str
    section_title: str
    coverage_status: str = Field(
        description="Coverage status: Fully Covered, Partially Covered, Missing, or No Impact"
    )
    gap_analysis: str = Field(
        description="Detailed analysis of the gap or coverage"
    )
    recommended_section: str | None = Field(
        default=None,
        description="Drafted policy section for Partially Covered or Missing sections"
    )


class PolicyGapAnalysisResponse(BaseModel):
    success: bool
    risk_id: int
    risk_title: str
    policy_name: str
    section_analyses: list[SectionGapAnalysis]
    summary: dict = Field(
        description="Summary counts of coverage statuses"
    )
