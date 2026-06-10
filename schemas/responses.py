from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class RiskResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: str
    title: str = Field(validation_alias="name")
    description: str
    category: list[str]
    level: str
    type: str = Field(validation_alias="riskType")
    areas_of_impact: list[str] = Field(
        validation_alias="areasOfImpact", serialization_alias="areasOfImpact"
    )
    owner_organization: str = Field(
        validation_alias="ownerOrganization", serialization_alias="ownerOrganization"
    )
    createdAt: datetime = Field(description="Read-only, set by the database")


class NotificationResponse(BaseModel):
    id: int
    riskId: str
    title: str
    viewed: bool
    createdAt: datetime


class CreateRiskResponse(BaseModel):
    success: bool
    risk: RiskResponse


class DismissNotificationResponse(BaseModel):
    success: bool


class RegulatoryChangeAlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alertId: str
    title: str
    nativeTitle: str | None = None
    category: str | None = None
    webUrl: str | None = None
    status: str | None = None
    regulatoryPublicationAndOntology: str | None = None
    ontology: str | None = None
    nativeContent: str | None = None
    classificationJurisdiction: str | None = None
    classificationCategory: str | None = None
    classificationApplicableJurisdictions: str | None = None
    classificationRegulatoryBodies: str | None = None
    keyDatesPublicationDate: str | None = None
    keyDatesIssuanceDate: str | None = None
    referenceIds: str | None = None
    referencesLinkUrl: str | None = None
    providedBy: str | None = None
    providedOn: str | None = None
    informationType: str | None = None
    impactedPolicies: list[str]


class PolicyImpact(BaseModel):
    policy_name: str
    rationale: str
    score: float = Field(ge=0, le=100, description="Impact score from 0-100%")


class AnalyzePolicyImpactResponse(BaseModel):
    success: bool
    risk_id: str
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
    risk_id: str
    risk_title: str
    policy_name: str
    section_analyses: list[SectionGapAnalysis]
    summary: dict = Field(
        description="Summary counts of coverage statuses"
    )
