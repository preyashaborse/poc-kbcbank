import logging
import os
import re
from pathlib import Path
from typing import List, Dict

from dotenv import load_dotenv
from langchain_community.document_loaders import PyPDFLoader
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field, ValidationError

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PolicySection(BaseModel):
    section_number: str = Field(description="Section number (e.g., '1', '2.1', '3.2.1')")
    section_title: str = Field(description="Title of the section")
    section_content: str = Field(description="Full content of the section")


class SectionCoverageAnalysis(BaseModel):
    section_number: str
    section_title: str
    coverage_status: str = Field(
        description="Must be one of: 'Fully Covered', 'Partially Covered', 'Missing', 'No Impact'"
    )
    gap_analysis: str = Field(
        description="Detailed explanation of coverage status and specific gaps identified"
    )
    recommended_section: str = Field(
        default="",
        description="Drafted policy section text to address gaps (only for Partially Covered or Missing)"
    )
    recommended_rationale: str = Field(
        default="",
        description="Rationale explaining why the recommended section addresses the identified gaps"
    )
    confidence_score: float = Field(
        default=0.0,
        description="Confidence score (0 to 100%) indicating the LLM's confidence in the analysis and recommendation"
    )


class PolicyGapAnalyzer:
    def __init__(self, policies_folder: str = "Files/policies"):
        self.policies_folder = Path(policies_folder)
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.error("OPENAI_API_KEY not found in environment variables")
            raise ValueError("OPENAI_API_KEY not found in environment variables")
        
        try:
            self.llm = ChatOpenAI(model="gpt-4o", temperature=0.3, api_key=api_key)
            logger.info(f"PolicyGapAnalyzer initialized with policies folder: {policies_folder}")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}", exc_info=True)
            raise
        
    def _normalize_policy_name(self, name: str) -> str:
        """Normalize policy names/ids for fuzzy file matching."""
        normalized = name.lower().strip()
        normalized = normalized.replace("&", " and ")
        normalized = normalized.replace("-", " ")
        normalized = normalized.replace("_", " ")
        return " ".join(normalized.split())

    def _extract_policy_id(self, filename: str) -> str | None:
        """Extract POL-xxx id from a policy filename."""
        stem = Path(filename).stem
        if not stem.upper().startswith("POL_"):
            return None
        parts = stem.split("_", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            return f"POL-{parts[1]}"
        return None

    def _find_policy_file(self, policy_name: str) -> Path | None:
        """Find the policy PDF file by name."""
        logger.debug(f"Searching for policy: {policy_name}")
        policy_files = list(self.policies_folder.glob("POL_*.pdf"))
        normalized_query = self._normalize_policy_name(policy_name)

        for policy_file in policy_files:
            file_policy_name = self._extract_policy_name(policy_file.name)
            normalized_file_name = self._normalize_policy_name(file_policy_name)
            file_policy_id = self._extract_policy_id(policy_file.name)

            if (
                normalized_query in normalized_file_name
                or normalized_file_name in normalized_query
                or (
                    file_policy_id
                    and self._normalize_policy_name(file_policy_id) == normalized_query
                )
            ):
                logger.info(f"Found policy file: {policy_file.name}")
                return policy_file

        logger.warning(f"Policy '{policy_name}' not found in {self.policies_folder}")
        return None
    
    def _extract_policy_name(self, filename: str) -> str:
        """Extract clean policy name from filename."""
        name = filename.replace(".pdf", "").replace("_", " ")
        if name.startswith("POL "):
            parts = name.split(" ", 2)
            if len(parts) >= 3:
                return parts[2]
        return name
    
    def _load_policy_content(self, policy_path: Path) -> str:
        """Load and extract text content from a policy PDF file."""
        try:
            logger.debug(f"Loading policy content from: {policy_path.name}")
            loader = PyPDFLoader(str(policy_path))
            pages = loader.load()
            content = "\n".join([page.page_content for page in pages])
            logger.info(f"Successfully loaded {len(pages)} pages from {policy_path.name}")
            return content
        except FileNotFoundError:
            logger.error(f"Policy file not found: {policy_path}")
            raise
        except Exception as e:
            logger.error(f"Error loading policy {policy_path.name}: {e}", exc_info=True)
            return ""
    
    def _parse_policy_sections(self, policy_content: str) -> List[PolicySection]:
        """
        Parse policy content into structured sections.
        Uses LLM to intelligently identify and extract sections.
        """
        parser = JsonOutputParser(pydantic_object=list[PolicySection])
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a policy document parser. Extract all sections from the policy document.
            
Your task:
1. Identify all major sections in the policy (e.g., Section 1, Section 2, etc.)
2. Extract the section number, title, and full content for each section
3. Include subsections as separate entries (e.g., 1.1, 1.2, 2.1)
4. Maintain the hierarchical structure

IMPORTANT RULES:
- SKIP cover page metadata sections (e.g., sections numbered "01", "Next Review", document metadata)
- ONLY extract sections from the main policy body content
- Each section number should appear ONLY ONCE
- If you see duplicate section numbers, extract only the one from the main policy body

Section patterns to look for:
- Numbered sections (1., 2., 3., etc.)
- Decimal sections (1.1, 1.2, 2.1, etc.)
- Named sections (Purpose, Scope, Definitions, etc.)
- Headings in bold or uppercase

{format_instructions}"""),
            ("user", """Policy Content:
{policy_content}

Extract all sections with their numbers, titles, and content. Remember to skip cover page sections and avoid duplicates.""")
        ])
        
        chain = prompt | self.llm | parser
        
        try:
            logger.debug("Parsing policy sections using LLM")
            sections = chain.invoke({
                "policy_content": policy_content[:15000],  # Limit for parsing
                "format_instructions": parser.get_format_instructions()
            })
            
            parsed_sections = [PolicySection(**section) for section in sections]
            deduplicated_sections = self._deduplicate_sections(parsed_sections)
            logger.info(f"Successfully parsed {len(deduplicated_sections)} sections using LLM (after deduplication)")
            return deduplicated_sections
        except ValidationError as e:
            logger.warning(f"Validation error parsing sections, using fallback: {e}")
            return self._fallback_section_parsing(policy_content)
        except Exception as e:
            logger.warning(f"Error parsing sections with LLM, using fallback: {e}")
            return self._fallback_section_parsing(policy_content)
    
    def _deduplicate_sections(self, sections: List[PolicySection]) -> List[PolicySection]:
        """
        Remove duplicate sections and filter out section "01" entries.
        Keeps the first occurrence of each section number.
        """
        seen_sections = set()
        deduplicated = []
        
        for section in sections:
            # Skip section "01" entries (cover page metadata)
            if section.section_number == "01":
                logger.debug(f"Filtering out section '01': {section.section_title}")
                continue
            
            # Keep first occurrence of each section number
            if section.section_number not in seen_sections:
                seen_sections.add(section.section_number)
                deduplicated.append(section)
            else:
                logger.debug(f"Removing duplicate section {section.section_number}: {section.section_title}")
        
        logger.info(f"Deduplication: {len(sections)} -> {len(deduplicated)} sections")
        return deduplicated
    
    def _fallback_section_parsing(self, policy_content: str) -> List[PolicySection]:
        """Fallback regex-based section parsing if LLM parsing fails."""
        logger.info("Using fallback regex-based section parsing")
        sections = []
        
        section_pattern = r'(?:^|\n)(\d+(?:\.\d+)*)\s*[.:]?\s*([A-Z][^\n]+?)(?=\n)'
        matches = re.finditer(section_pattern, policy_content, re.MULTILINE)
        
        matches_list = list(matches)
        for i, match in enumerate(matches_list):
            section_num = match.group(1)
            section_title = match.group(2).strip()
            
            start_pos = match.end()
            end_pos = matches_list[i + 1].start() if i + 1 < len(matches_list) else len(policy_content)
            section_content = policy_content[start_pos:end_pos].strip()
            
            sections.append(PolicySection(
                section_number=section_num,
                section_title=section_title,
                section_content=section_content[:1000]  # Limit content length
            ))
        
        if not sections:
            logger.warning("No sections found with regex, creating single section")
            sections.append(PolicySection(
                section_number="1",
                section_title="Full Policy Content",
                section_content=policy_content[:2000]
            ))
        else:
            logger.info(f"Fallback parsing found {len(sections)} sections")
        
        return self._deduplicate_sections(sections)
    
    def _analyze_section_coverage(
        self,
        section: PolicySection,
        risk_title: str,
        risk_description: str,
        policy_name: str
    ) -> SectionCoverageAnalysis:
        """Analyze a single section's coverage of the risk and draft recommendations if needed."""
        
        parser = JsonOutputParser(pydantic_object=SectionCoverageAnalysis)
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are an expert GRC (Governance, Risk, and Compliance) analyst specializing in policy gap analysis.

Your task is to analyze whether a specific policy section adequately addresses a given risk.

Classification criteria:

1. **Fully Covered**: The section contains comprehensive controls, procedures, or requirements that fully address all aspects of the risk. No gaps exist.

2. **Partially Covered**: The section addresses some aspects of the risk but has notable gaps. Some controls exist but are incomplete, outdated, or insufficient.

3. **Missing**: The section has no coverage of the risk, or the coverage is so minimal it's effectively absent. Critical controls are completely missing.

4. **No Impact**: The section's subject matter is not relevant to this specific risk. There's no logical connection between the section and the risk.

For **Partially Covered** or **Missing** sections:
- Draft a new policy section or subsection that addresses the identified gaps
- Use professional policy language
- Include specific, actionable requirements
- Reference relevant regulatory frameworks where applicable
- Format as a complete policy section with clear requirements
- Provide a clear rationale explaining why this recommendation addresses the gaps
- Assign a confidence score (0 to 100%) based on:
  * Clarity of the gap identified (30%)
  * Relevance of the recommendation to the risk (40%)
  * Completeness of the proposed solution (30%)

{format_instructions}"""),
            ("user", """Policy Name: {policy_name}

Section {section_number}: {section_title}
Section Content:
{section_content}

Risk Title: {risk_title}
Risk Description: {risk_description}

Analyze this section's coverage of the risk and provide:
1. Coverage status (Fully Covered, Partially Covered, Missing, or No Impact)
2. Detailed gap analysis
3. If Partially Covered or Missing:
   - Draft a new policy section to address the gaps
   - Provide a rationale explaining why this recommendation addresses the identified gaps
   - Assign a confidence score (0.0 to 1.0) reflecting your confidence in the analysis and recommendation""")
        ])
        
        chain = prompt | self.llm | parser
        
        try:
            logger.debug(f"Analyzing section {section.section_number}: {section.section_title}")
            result = chain.invoke({
                "policy_name": policy_name,
                "section_number": section.section_number,
                "section_title": section.section_title,
                "section_content": section.section_content,
                "risk_title": risk_title,
                "risk_description": risk_description,
                "format_instructions": parser.get_format_instructions()
            })
            
            analysis = SectionCoverageAnalysis(**result)
            logger.info(f"Section {section.section_number} analyzed - Status: {analysis.coverage_status}")
            return analysis
        except ValidationError as e:
            logger.error(f"Validation error analyzing section {section.section_number}: {e}", exc_info=True)
            return SectionCoverageAnalysis(
                section_number=section.section_number,
                section_title=section.section_title,
                coverage_status="No Impact",
                gap_analysis=f"Analysis failed due to validation error: {str(e)}",
                recommended_section="",
                recommended_rationale="",
                confidence_score=0.0
            )
        except Exception as e:
            logger.error(f"Error analyzing section {section.section_number}: {e}", exc_info=True)
            return SectionCoverageAnalysis(
                section_number=section.section_number,
                section_title=section.section_title,
                coverage_status="No Impact",
                gap_analysis=f"Analysis failed: {str(e)}",
                recommended_section="",
                recommended_rationale="",
                confidence_score=0.0
            )
    
    def analyze_policy_gaps(
        self,
        risk_id: int,
        risk_title: str,
        risk_description: str,
        policy_name: str
    ) -> Dict:
        """
        Perform comprehensive section-level gap analysis for a policy against a risk.
        
        Args:
            risk_id: ID of the risk
            risk_title: Title of the risk
            risk_description: Description of the risk
            policy_name: Name of the policy to analyze
            
        Returns:
            Dictionary containing section analyses and summary statistics
        """
        logger.info(f"Starting gap analysis for policy '{policy_name}' against risk_id={risk_id}")
        
        policy_file = self._find_policy_file(policy_name)
        
        if not policy_file:
            logger.error(f"Policy '{policy_name}' not found in {self.policies_folder}")
            raise ValueError(f"Policy '{policy_name}' not found in {self.policies_folder}")
        
        policy_content = self._load_policy_content(policy_file)
        
        if not policy_content:
            logger.error(f"Failed to load content from policy '{policy_name}'")
            raise ValueError(f"Failed to load content from policy '{policy_name}'")
        
        sections = self._parse_policy_sections(policy_content)
        
        if not sections:
            logger.error(f"No sections found in policy '{policy_name}'")
            raise ValueError(f"No sections found in policy '{policy_name}'")
        
        logger.info(f"Analyzing {len(sections)} sections")
        section_analyses = []
        
        for section in sections:
            analysis = self._analyze_section_coverage(
                section=section,
                risk_title=risk_title,
                risk_description=risk_description,
                policy_name=policy_name
            )
            section_analyses.append(analysis)
        
        summary = {
            "total_sections": len(section_analyses),
            "fully_covered": sum(1 for a in section_analyses if a.coverage_status == "Fully Covered"),
            "partially_covered": sum(1 for a in section_analyses if a.coverage_status == "Partially Covered"),
            "missing": sum(1 for a in section_analyses if a.coverage_status == "Missing"),
            "no_impact": sum(1 for a in section_analyses if a.coverage_status == "No Impact"),
            "sections_needing_action": sum(
                1 for a in section_analyses 
                if a.coverage_status in ["Partially Covered", "Missing"]
            )
        }
        
        logger.info(f"Gap analysis complete. Summary: {summary}")
        
        return {
            "section_analyses": section_analyses,
            "summary": summary
        }
