from langchain.output_parsers import PydanticOutputParser
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field


class _RewritingFinding(BaseModel):
    section_reference: str = Field(description="Section reference or location in the policy")
    issue: str = Field(description="Description of the issue identified")
    proposed_rewrite: str = Field(description="Proposed rewrite or improvement")
    rationale: str = Field(description="Explanation of why this change improves the policy")
    score: float = Field(ge=0, le=100, description="Score for this specific finding (0-100)")


class _DimensionAnalysis(BaseModel):
    findings: list[_RewritingFinding] = Field(default_factory=list)
    dimension_score: float = Field(ge=0, le=100, description="Overall score for this dimension (0-100)")
    dimension_rationale: str = Field(description="Overall rationale for the dimension score")


class _RewritingReport(BaseModel):
    clarity_and_language: _DimensionAnalysis
    structure_and_formatting: _DimensionAnalysis
    machine_readability: _DimensionAnalysis
    consistency: _DimensionAnalysis
    overall_score: float = Field(ge=0, le=100, description="Overall weighted score (0-100)")
    overall_rationale: str = Field(description="Explanation of how overall score was calculated")


SYSTEM_PROMPT = """You are an expert policy analyst and technical writer specializing in policy improvement and optimization.

Your task is to analyze policies across four critical dimensions and provide structured, actionable improvement recommendations.

## Analysis Dimensions

### 1. Clarity and Language
Identify content that is:
- Unclear or ambiguous (multiple interpretations possible)
- Redundant or repetitive
- Overly complex or jargon-heavy without explanation
- Inconsistent in terminology or phrasing

For each issue, propose simplified rewording that maintains the original intent while improving readability.

### 2. Structure and Formatting
Evaluate the policy against the provided organizational template:
- Check section order and logical flow
- Identify missing sections that should be present
- Flag misplaced content that belongs in different sections
- Assess consistency of formatting and structure

### 3. Machine Readability
Identify content that cannot be easily parsed or processed:
- Images without captions or descriptions
- Malformed or poorly structured tables
- Unparseable content (corrupted text, unclear formatting)
- Missing metadata or context for automated processing

### 4. Consistency
Identify terminology and concept mismatches:
- Terms used inconsistently throughout the document
- Conflicting definitions or descriptions of the same concept
- Inconsistent formatting of similar elements
- Contradictory statements or requirements

## Output Requirements

For each dimension:
1. List all findings with section references
2. For each finding, provide:
   - Section reference (e.g., "Section 3.2 Air Travel")
   - Issue description
   - Proposed rewrite or improvement
   - Rationale for the change
   - Score for that specific finding (0-100, where 100 is no issue)
3. Calculate an overall dimension score (0-100)
4. Provide rationale for the dimension score

For the overall analysis:
- Calculate an overall weighted score (0-100) using the best weighting approach
- Explain how the overall score was calculated
- Consider all four dimensions in the weighting

## Important Notes

- Be specific and actionable in your recommendations
- Reference exact sections or locations in the policy
- Provide clear rationale for each improvement
- Scores should reflect the severity/impact of issues (lower scores = more critical issues)
- Do NOT make assumptions about policy content - only analyze what is provided
- Do NOT recommend policy changes based on judgment - focus on clarity, structure, readability, and consistency only
"""


class PolicyRewritingAnalyzer:
    def __init__(self, openai_api_key: str):
        self.llm = ChatOpenAI(
            model="gpt-4",
            temperature=0.3,
            api_key=openai_api_key,
        )
        self.parser = PydanticOutputParser(pydantic_object=_RewritingReport)

    async def analyze_rewriting(
        self, policy_content: str, template_context: str
    ) -> dict:
        """
        Analyze a policy for improvements across four dimensions.
        
        Args:
            policy_content: The full policy text to analyze
            template_context: The organizational policy template for reference
            
        Returns:
            Dictionary with analysis results
        """
        report = await self._run_llm_analysis(policy_content, template_context)
        return self._normalize_report(report)

    async def _run_llm_analysis(
        self, policy_content: str, template_context: str
    ) -> _RewritingReport:
        """Run the LLM analysis on the policy."""
        user_content = f"""Analyze the following policy against the provided organizational template.

ORGANIZATIONAL TEMPLATE (for reference and structure):
{template_context[:8000]}

POLICY TO ANALYZE:
{policy_content[:12000]}

Provide comprehensive analysis across all four dimensions. For each finding, include:
- Exact section reference from the policy
- Clear description of the issue
- Proposed rewrite or improvement
- Rationale for why this improves the policy
- Score for that specific finding (0-100)

Then provide overall scores and rationale for each dimension, and finally an overall weighted score.

{self.parser.get_format_instructions()}"""

        from langchain_core.messages import HumanMessage, SystemMessage

        response = await self.llm.ainvoke(
            [
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=user_content),
            ]
        )

        parsed_output = self.parser.parse(response.content)
        return parsed_output

    def _normalize_report(self, report: _RewritingReport) -> dict:
        """Convert the LLM report to a normalized dictionary format."""
        dimensions = {
            "clarity_and_language": report.clarity_and_language,
            "structure_and_formatting": report.structure_and_formatting,
            "machine_readability": report.machine_readability,
            "consistency": report.consistency,
        }

        result = {}
        for name, dimension in dimensions.items():
            result[name] = {
                "findings": [
                    {
                        "section_reference": f.section_reference,
                        "issue": f.issue,
                        "proposed_rewrite": f.proposed_rewrite,
                        "rationale": f.rationale,
                        "score": f.score,
                    }
                    for f in dimension.findings
                ],
                "dimension_score": dimension.dimension_score,
                "dimension_rationale": dimension.dimension_rationale,
            }

        result["overall_score"] = report.overall_score
        result["overall_rationale"] = report.overall_rationale
        return result
