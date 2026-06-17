import json
import logging
import os
import re
from typing import Any

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.output_parsers import JsonOutputParser
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field, ValidationError

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

METADATA_ATTRIBUTES = [
    "Country",
    "Region",
    "Retention Period",
    "Department",
    "Legal Hold",
    "Material Change",
    "Regulatory",
    "Customer",
    "Jurisdiction",
    "Regulation",
    "Language",
]

SYSTEM_PROMPT = """You are an AI Metadata Tagging Engine integrated into MetricStream Policy Management (PDMS).

Your task is to analyse an open policy form — including policy body text, section content, descriptions, controls, risks, and references — and propose values for PDMS metadata fields.

## Metadata attributes to extract

For each attribute below, propose a single value inferred only from the provided form data and policy content. Do not invent facts not supported by the text.

| Attribute | What to infer |
|-----------|----------------|
| Country | Primary country or countries the policy applies to (e.g. Belgium, Global, Multi-country). |
| Region | Geographic or business region (e.g. Europe, EMEA, Belgium, Group-wide). |
| Retention Period | Document or records retention period if stated or reasonably implied (e.g. "7 years", "Life of policy + 5 years"). If not stated, use "Not specified in policy". |
| Department | Owning or accountable department/function (e.g. Risk Management, Compliance, HR). |
| Legal Hold | Whether legal hold requirements are mentioned (Yes / No / Not specified). |
| Material Change | Whether the policy describes or implies material change processes (Yes / No / Not specified). |
| Regulatory | Primary regulatory themes or regimes referenced (e.g. GDPR, DORA, Belgian tax law). |
| Customer | Whether policy relates to customer-facing activities or customer impact (Yes / No / Partial / Not applicable). |
| Jurisdiction | Legal or regulatory jurisdiction governing the policy (e.g. Belgium, EU, KBC Group). |
| Regulation | Specific regulations, directives, or internal standards cited (comma-separated if multiple). |
| Language | Primary language of the policy document (e.g. English, Dutch, French, bilingual). |

## Confidence scoring (0–100)

Assign a confidence score for each proposed value:

- 90–100: Explicitly stated in the policy text or form metadata.
- 70–89: Strongly implied from context with clear supporting excerpts.
- 50–69: Reasonable inference with partial or indirect evidence.
- Below 50: Weak inference; use when evidence is minimal.

If the attribute cannot be determined from the content, set extracted_value to "Not identified in policy" and confidence_score between 10–40.

## Rules

- Use only information present in the supplied form fields and policy template text.
- Prefer concise, PDMS-ready values (short phrases, not paragraphs).
- For Yes/No style fields (Legal Hold, Material Change, Customer), use only: Yes, No, Partial, Not applicable, or Not specified.
- Do not approve or publish the policy; proposals are advisory for SME review.
- Return exactly one entry per attribute listed above (11 entries total).

Return ONLY valid JSON matching the required schema."""


class _LLMMetadataProposal(BaseModel):
    attribute_name: str
    extracted_value: str
    confidence_score: float = Field(ge=0, le=100)


class _LLMMetadataReport(BaseModel):
    proposals: list[_LLMMetadataProposal]


class MetadataTaggingAnalyzer:
    def __init__(self, confidence_threshold: float | None = None):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY not found in environment variables")

        threshold_raw = os.getenv("METADATA_CONFIDENCE_THRESHOLD", "70")
        try:
            default_threshold = float(threshold_raw)
        except ValueError:
            default_threshold = 70.0

        self.confidence_threshold = (
            confidence_threshold if confidence_threshold is not None else default_threshold
        )
        self.confidence_threshold = max(0.0, min(100.0, self.confidence_threshold))

        self.llm = ChatOpenAI(model="gpt-4o", temperature=0.2, api_key=api_key)
        self.parser = JsonOutputParser(pydantic_object=_LLMMetadataReport)
        logger.info(
            f"MetadataTaggingAnalyzer initialized (threshold={self.confidence_threshold})"
        )

    def _build_form_context(self, form_data: dict[str, Any]) -> str:
        lines = [
            f"Document Name: {form_data.get('documentName', '')}",
            f"Document Type: {form_data.get('documentType', '')}",
            f"Approval Type: {form_data.get('approvalType', '')}",
            f"Category: {form_data.get('category', '')}",
            f"Description: {form_data.get('description', '')}",
            f"Effective From: {form_data.get('effectiveFrom', '')}",
        ]

        controls = form_data.get("controls") or []
        if controls:
            lines.append("Linked Controls:")
            lines.extend(f"- {c}" for c in controls)

        risks = form_data.get("relatedRisks") or []
        if risks:
            lines.append("Linked Risks:")
            lines.extend(f"- {r}" for r in risks)

        references = form_data.get("references") or []
        if references:
            lines.append("References:")
            for ref in references:
                url = ref.get("url", "") if isinstance(ref, dict) else str(ref)
                lines.append(f"- {url}")

        template = form_data.get("template") or ""
        lines.append("")
        lines.append("POLICY BODY (sections and content):")
        lines.append(template[:14000])

        return "\n".join(lines)

    def _parse_llm_report(self, raw: str) -> _LLMMetadataReport:
        try:
            parsed = self.parser.parse(raw)
            if isinstance(parsed, _LLMMetadataReport):
                return parsed
            return _LLMMetadataReport.model_validate(parsed)
        except (ValidationError, json.JSONDecodeError, TypeError) as e:
            logger.warning(f"Metadata JSON parse failed, extracting JSON block: {e}")
            json_match = re.search(r"\{.*\}", raw, re.DOTALL)
            if not json_match:
                raise ValueError("LLM did not return valid JSON for metadata tagging") from e
            return _LLMMetadataReport.model_validate(json.loads(json_match.group()))

    def _normalize_proposals(self, report: _LLMMetadataReport) -> list[dict]:
        by_name: dict[str, _LLMMetadataProposal] = {}
        for proposal in report.proposals:
            key = proposal.attribute_name.strip().lower()
            by_name[key] = proposal

        normalized: list[dict] = []
        for attribute in METADATA_ATTRIBUTES:
            match = by_name.get(attribute.lower())
            if match:
                extracted_value = match.extracted_value.strip()
                confidence = float(match.confidence_score)
            else:
                extracted_value = "Not identified in policy"
                confidence = 20.0

            confidence = max(0.0, min(100.0, confidence))
            normalized.append(
                {
                    "attribute_name": attribute,
                    "extracted_value": extracted_value,
                    "confidence_score": round(confidence, 1),
                    "requires_review": confidence < self.confidence_threshold,
                }
            )

        return normalized

    async def extract_metadata(self, form_data: dict[str, Any]) -> dict:
        template = form_data.get("template") or ""
        if not template.strip():
            raise ValueError("Policy template content is required for metadata tagging")

        form_context = self._build_form_context(form_data)
        attribute_list = "\n".join(f"- {name}" for name in METADATA_ATTRIBUTES)

        user_content = f"""Analyse the following open PDMS policy form and propose metadata values.

Extract proposals for ALL of these attributes:
{attribute_list}

FORM AND POLICY CONTENT:
{form_context}

{self.parser.get_format_instructions()}"""

        response = await self.llm.ainvoke(
            [
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=user_content),
            ]
        )

        raw = response.content if isinstance(response.content, str) else str(response.content)
        report = self._parse_llm_report(raw)
        proposals = self._normalize_proposals(report)

        logger.info(f"Metadata tagging completed: {len(proposals)} attributes proposed")

        return {
            "success": True,
            "confidence_threshold": self.confidence_threshold,
            "proposals": proposals,
        }
