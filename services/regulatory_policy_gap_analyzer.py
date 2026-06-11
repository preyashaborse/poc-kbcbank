import json
import logging
from typing import Dict, List

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field, ValidationError

from services.policy_gap_analyzer import PolicyGapAnalyzer, PolicySection

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class RegulatorySectionCoverageAnalysis(BaseModel):
    section_number: str
    section_title: str
    coverage_status: str = Field(
        description="Must be one of: 'Fully Covered', 'Partially Covered', 'Missing', or 'No Impact'"
    )
    gap_analysis: str = Field(
        description="Detailed explanation of coverage status and specific gaps identified"
    )
    matched_obligations: List[str] = Field(
        default_factory=list,
        description="Obligation IDs this section addresses or partially addresses",
    )
    recommended_section: str = Field(
        default="",
        description="Drafted policy section text to address gaps (only for Partially Covered or Missing)",
    )
    recommended_rationale: str = Field(default="")
    confidence_score: float = Field(default=0.0, ge=0, le=100)


class RegulatoryPolicyGapAnalyzer:
    """Section-level gap analysis of a policy against regulatory obligations."""

    def __init__(self, policies_folder: str = "Files/policies"):
        self._policy_analyzer = PolicyGapAnalyzer(policies_folder=policies_folder)
        self.llm = self._policy_analyzer.llm

    def _format_obligations(self, obligations: List[Dict]) -> str:
        return json.dumps(obligations, indent=2, ensure_ascii=False)

    def _analyze_section_obligation_coverage(
        self,
        section: PolicySection,
        obligations: List[Dict],
        regulatory_content: str,
        alert_title: str,
        policy_name: str,
    ) -> RegulatorySectionCoverageAnalysis:
        parser = JsonOutputParser(pydantic_object=RegulatorySectionCoverageAnalysis)

        prompt = ChatPromptTemplate.from_messages([
            (
                "system",
                """You are an expert regulatory compliance analyst specializing in policy gap analysis.

Your task is to analyze whether a specific policy section adequately addresses the regulatory obligations extracted from a regulatory change alert.

Classification criteria:

1. **Fully Covered**: The section contains comprehensive controls, procedures, or requirements that fully address all relevant obligations applicable to this section. No gaps exist.

2. **Partially Covered**: The section addresses some relevant obligations but has notable gaps. Some controls exist but are incomplete, outdated, or insufficient.

3. **Missing**: The section has no meaningful coverage of the relevant obligations, or coverage is so minimal it is effectively absent.

4. **No Impact**: The section's subject matter is not relevant to any of the listed obligations.

For **Partially Covered** or **Missing** sections:
- Draft a new policy section or subsection that addresses the identified gaps
- Use professional policy language with specific, actionable requirements
- Reference relevant obligation IDs in matched_obligations and gap_analysis
- Provide rationale for the recommended draft
- Assign a confidence score (0 to 100)

Always list obligation IDs in matched_obligations when the section relates to them (fully or partially).

{format_instructions}""",
            ),
            (
                "user",
                """Regulatory Alert Title: {alert_title}

Regulatory Content Summary:
{regulatory_content}

Extracted Obligations:
{obligations}

Policy Name: {policy_name}

Section {section_number}: {section_title}
Section Content:
{section_content}

Analyze this section's coverage of the regulatory obligations and provide:
1. Coverage status (Fully Covered, Partially Covered, Missing, or No Impact)
2. Detailed gap analysis referencing specific obligation IDs where relevant
3. matched_obligations: list of obligation IDs this section relates to
4. If Partially Covered or Missing: draft recommended_section and recommended_rationale""",
            ),
        ])

        chain = prompt | self.llm | parser

        try:
            logger.debug(
                f"Analyzing section {section.section_number} against regulatory obligations"
            )
            result = chain.invoke({
                "alert_title": alert_title,
                "regulatory_content": regulatory_content[:8000],
                "obligations": self._format_obligations(obligations),
                "policy_name": policy_name,
                "section_number": section.section_number,
                "section_title": section.section_title,
                "section_content": section.section_content,
                "format_instructions": parser.get_format_instructions(),
            })
            analysis = RegulatorySectionCoverageAnalysis(**result)
            logger.info(
                f"Section {section.section_number} analyzed - Status: {analysis.coverage_status}"
            )
            return analysis
        except ValidationError as e:
            logger.error(
                f"Validation error analyzing section {section.section_number}: {e}",
                exc_info=True,
            )
            return RegulatorySectionCoverageAnalysis(
                section_number=section.section_number,
                section_title=section.section_title,
                coverage_status="No Impact",
                gap_analysis=f"Analysis failed due to validation error: {str(e)}",
            )
        except Exception as e:
            logger.error(
                f"Error analyzing section {section.section_number}: {e}",
                exc_info=True,
            )
            return RegulatorySectionCoverageAnalysis(
                section_number=section.section_number,
                section_title=section.section_title,
                coverage_status="No Impact",
                gap_analysis=f"Analysis failed: {str(e)}",
            )

    def analyze_regulatory_policy_gaps(
        self,
        alert_title: str,
        regulatory_content: str,
        obligations: List[Dict],
        policy_name: str,
    ) -> Dict:
        """Perform section-level gap analysis for a policy against regulatory obligations."""
        logger.info(
            f"Starting regulatory gap analysis for policy '{policy_name}' "
            f"with {len(obligations)} obligations"
        )

        if not obligations:
            raise ValueError("At least one obligation is required for regulatory gap analysis")

        policy_file = self._policy_analyzer._find_policy_file(policy_name)
        if not policy_file:
            raise ValueError(f"Policy '{policy_name}' not found in {self._policy_analyzer.policies_folder}")

        policy_content = self._policy_analyzer._load_policy_content(policy_file)
        if not policy_content:
            raise ValueError(f"Failed to load content from policy '{policy_name}'")

        sections = self._policy_analyzer._parse_policy_sections(policy_content)
        if not sections:
            raise ValueError(f"No sections found in policy '{policy_name}'")

        logger.info(f"Analyzing {len(sections)} sections against regulatory obligations")
        section_analyses: List[RegulatorySectionCoverageAnalysis] = []

        for section in sections:
            analysis = self._analyze_section_obligation_coverage(
                section=section,
                obligations=obligations,
                regulatory_content=regulatory_content,
                alert_title=alert_title,
                policy_name=policy_name,
            )
            section_analyses.append(analysis)

        summary = {
            "total_sections": len(section_analyses),
            "fully_covered": sum(
                1 for a in section_analyses if a.coverage_status == "Fully Covered"
            ),
            "partially_covered": sum(
                1 for a in section_analyses if a.coverage_status == "Partially Covered"
            ),
            "missing": sum(1 for a in section_analyses if a.coverage_status == "Missing"),
            "no_impact": sum(1 for a in section_analyses if a.coverage_status == "No Impact"),
            "sections_needing_action": sum(
                1
                for a in section_analyses
                if a.coverage_status in ["Partially Covered", "Missing"]
            ),
        }

        logger.info(f"Regulatory gap analysis complete. Summary: {summary}")
        return {
            "section_analyses": section_analyses,
            "summary": summary,
        }
