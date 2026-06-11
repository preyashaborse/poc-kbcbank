from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class RiskResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: str
    title: str = Field(validation_alias="name")
    description: str
    category: str
    level: str
    type: str = Field(validation_alias="riskType")
    areas_of_impact: str = Field(
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


class Obligation(BaseModel):
    obligation_id: str
    obligation_text: str
    obligation_category: str
    priority: str
    rationale: str


class RegulatorySectionGapAnalysis(BaseModel):
    section_number: str
    section_title: str
    coverage_status: str = Field(
        description="Fully Covered, Partially Covered, Missing, or No Impact"
    )
    gap_analysis: str
    matched_obligations: list[str] = []
    recommended_section: str | None = None


class RegulatoryPolicyGapAnalysisResponse(BaseModel):
    success: bool
    alert_id: str
    alert_title: str
    policy_name: str
    obligations: list[Obligation]
    section_analyses: list[RegulatorySectionGapAnalysis]
    summary: dict = Field(description="Summary counts of coverage statuses")


class PolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    policy_id: str
    policy_title: str
    business_line: str | None = None
    policy_owner: str | None = None
    version: str | None = None
    status: str | None = None
    risk_level: str | None = None


class PolicyDocumentReference(BaseModel):
    url: str


class PolicyDocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    documentName: str
    documentType: str | None = None
    approvalType: str | None = None
    category: str | None = None
    description: str | None = None
    effectiveFrom: str | None = None
    template: str | None = None
    references: list[PolicyDocumentReference] = []
    controls: list[str] = []
    relatedRisks: list[str] = []


class ExtractObligationsResponse(BaseModel):
    success: bool
    alert_id: str
    title: str
    obligations: list[Obligation]


class RankedPolicy(BaseModel):
    policy_id: str
    policy_title: str
    relevance_score: float
    rationale: str
    matched_obligations: list[str] = []


class AnalyzeLinkedPolicyResponse(BaseModel):
    success: bool
    alert_id: str | None = None
    obligations: list[Obligation]
    ranked_policies: list[RankedPolicy]


class Finding(BaseModel):
    finding_id: str
    finding_type: str = Field(description="CONFLICT, INCONSISTENCY, BLIND_SPOT, or CONTROL_RISK")
    severity: str = Field(description="Blocking, Non-Blocking, or Advisory")
    title: str
    description: str
    affected_sections: list[str] = Field(description="Section numbers/references affected")
    cited_excerpts: list[str] = Field(description="Verbatim excerpts from policy")
    confidence_score: float = Field(ge=0, le=100, description="Confidence score 0-100%")
    confidence_reason: str = Field(description="One-line reason for confidence score")
    cross_document_refs: list[str] = Field(default=[], description="References to other documents")
    remediation_notes: str = Field(default="", description="Policy owner notes, not recommendations")


class ControlAnalysis(BaseModel):
    control_id: str
    control_text: str
    status: str = Field(description="Enforceable, Partially Enforceable, or Unenforceable")
    linked_findings: list[str] = Field(description="Finding IDs that affect this control")
    notes: str


class RiskAnalysis(BaseModel):
    risk_id: str
    risk_text: str
    status: str = Field(description="Mitigated, Partially Mitigated, or Unmitigated")
    policy_coverage: str = Field(description="Fully Covered, Partially Covered, or Uncovered")
    linked_findings: list[str] = Field(description="Finding IDs related to this risk")
    notes: str


class ReviewAnalysisResponse(BaseModel):
    success: bool
    document_name: str
    document_id: str
    document_version: str
    analysis_timestamp: datetime
    findings: list[Finding]
    control_analysis: list[ControlAnalysis]
    risk_analysis: list[RiskAnalysis]
    summary: dict = Field(description="Summary counts by finding type and severity")
    overall_compliance_status: str = Field(description="Compliant, Compliant with Exceptions, or Non-Compliant")
