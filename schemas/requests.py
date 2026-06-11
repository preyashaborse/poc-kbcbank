from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class CreateRiskRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    title: str
    name: str
    description: Optional[str] = ""
    level: str
    category: str
    categories: Optional[str] = ""
    type: Optional[str] = ""
    areas_of_impact: Optional[str] = Field(default="", alias="areasOfImpact")
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


class AnalyzeLinkedPolicyRequest(BaseModel):
    alertId: Optional[str] = None
    regulatoryContent: Optional[str] = None
    obligations: Optional[list[dict]] = None


class ExtractObligationsRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    extracted_document_text: Optional[str] = Field(default=None, alias="extractedDocumentText")


class RegulatoryPolicyGapAnalysisRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    policy_name: str
    obligations: Optional[list[dict]] = None
    extracted_document_text: Optional[str] = Field(default=None, alias="extractedDocumentText")

