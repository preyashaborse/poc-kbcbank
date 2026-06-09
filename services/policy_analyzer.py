import logging
import os
from pathlib import Path
from typing import List

from dotenv import load_dotenv
from langchain_community.document_loaders import PyPDFLoader
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field, ValidationError

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class PolicyImpactAnalysis(BaseModel):
    policy_name: str = Field(description="Name of the policy")
    rationale: str = Field(
        description="Detailed explanation of how the risk impacts this policy")
    score: float = Field(description="Impact score from 0-100", ge=0, le=100)


class PolicyAnalyzer:
    def __init__(self, policies_folder: str = "Files/policies"):
        self.policies_folder = Path(policies_folder)
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.error("OPENAI_API_KEY not found in environment variables")
            raise ValueError(
                "OPENAI_API_KEY not found in environment variables")

        try:
            self.llm = ChatOpenAI(
                model="gpt-4o", temperature=0.3, api_key=api_key)
            self.embeddings = OpenAIEmbeddings(api_key=api_key)
            logger.info(
                f"PolicyAnalyzer initialized with policies folder: {policies_folder}")
        except Exception as e:
            logger.error(
                f"Failed to initialize OpenAI clients: {e}", exc_info=True)
            raise

    def _load_policy_content(self, policy_path: Path) -> str:
        """Load and extract text content from a policy PDF file."""
        try:
            logger.debug(f"Loading policy content from: {policy_path.name}")
            loader = PyPDFLoader(str(policy_path))
            pages = loader.load()
            content = "\n".join([page.page_content for page in pages])
            logger.info(
                f"Successfully loaded {len(pages)} pages from {policy_path.name}")
            return content[:12000]  # Limit content to avoid token limits
        except FileNotFoundError:
            logger.error(f"Policy file not found: {policy_path}")
            raise
        except Exception as e:
            logger.error(
                f"Error loading policy {policy_path.name}: {e}", exc_info=True)
            return ""

    def _get_policy_name(self, filename: str) -> str:
        """Extract clean policy name from filename."""
        name = filename.replace(".pdf", "").replace("_", " ")
        if name.startswith("POL "):
            parts = name.split(" ", 2)
            if len(parts) >= 3:
                return parts[2]
        return name

    def _analyze_single_policy(
        self,
        policy_name: str,
        policy_content: str,
        risk_title: str,
        risk_description: str
    ) -> PolicyImpactAnalysis:
        """Analyze impact of a risk on a single policy using LLM."""

        parser = JsonOutputParser(pydantic_object=PolicyImpactAnalysis)

        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a senior risk and compliance analyst.
Given a RISK and a POLICY, your job is to analyze how the risk impacts 
compliance with that policy.
---
## YOUR PROCESS

**Step 1 — Assess the relationship**
Identify specifically which controls or obligations within the policy 
are affected by the risk. If there is no meaningful relationship, 
set impact_score to 0 and explain why.

**Step 2 — Score the impact (0–100)**
Weigh these factors to arrive at a single score:
- Does the risk directly violate or undermine the policy's core purpose? (most important)
- How many of the policy's controls are affected?
- Are existing mitigations already covering this risk under the policy?
- What is the severity of the gap if the risk materializes?

Anchor reference:
| Range  | Meaning                                                      |
|--------|--------------------------------------------------------------|
|  0–20  | Policy is barely relevant to this risk                       |
| 21–40  | Tangential — minor overlap, limited control gaps             |
| 41–60  | Moderate — clear relationship, some meaningful control gaps  |
| 61–80  | High — policy is a primary control, significant gaps exposed |
| 81–100 | Critical — risk directly breaks the policy's core objective  |

**Step 3 — Justify your score**
Your rationale must reference specific policy controls and explain 
exactly how the risk undermines them. Vague justifications are not 
acceptable.

Be CRITICAL and PRECISE - not all high impacts are equal.

{format_instructions}"""),
            ("user", """Policy Name: {policy_name}

Policy Content (excerpt):
{policy_content}

Risk Title: {risk_title}
Risk Description: {risk_description}

Analyze the impact of this risk on the policy.""")
        ])

        chain = prompt | self.llm | parser

        try:
            logger.debug(
                f"Analyzing policy: {policy_name} against risk: {risk_title}")
            result = chain.invoke({
                "policy_name": policy_name,
                "policy_content": policy_content,
                "risk_title": risk_title,
                "risk_description": risk_description,
                "format_instructions": parser.get_format_instructions()
            })

            analysis = PolicyImpactAnalysis(**result)
            logger.info(
                f"Policy {policy_name} analyzed - Impact score: {analysis.score}")
            return analysis
        except ValidationError as e:
            logger.error(
                f"Validation error for policy {policy_name}: {e}", exc_info=True)
            return PolicyImpactAnalysis(
                policy_name=policy_name,
                rationale="Analysis failed due to validation error",
                score=0.0
            )
        except Exception as e:
            logger.error(
                f"Error analyzing policy {policy_name}: {e}", exc_info=True)
            return PolicyImpactAnalysis(
                policy_name=policy_name,
                rationale=f"Analysis failed: {str(e)}",
                score=0.0
            )

    def analyze_risk_impact(
        self,
        risk_id: int,
        risk_title: str,
        risk_description: str,
        top_n: int = 5
    ) -> List[PolicyImpactAnalysis]:
        """
        Analyze which policies are most impacted by the given risk.

        Args:
            risk_id: ID of the risk
            risk_title: Title of the risk
            risk_description: Description of the risk
            top_n: Number of top impacted policies to return

        Returns:
            List of PolicyImpactAnalysis objects sorted by impact score
        """
        logger.info(
            f"Starting risk impact analysis for risk_id={risk_id}: {risk_title}")
        policy_files = list(self.policies_folder.glob("POL_*.pdf"))

        if not policy_files:
            logger.error(f"No policy files found in {self.policies_folder}")
            raise ValueError(
                f"No policy files found in {self.policies_folder}")

        logger.info(f"Found {len(policy_files)} policy files to analyze")
        analyses = []

        for policy_file in policy_files:
            policy_name = self._get_policy_name(policy_file.name)
            policy_content = self._load_policy_content(policy_file)

            if not policy_content:
                logger.warning(
                    f"Skipping policy {policy_name} - empty content")
                continue

            analysis = self._analyze_single_policy(
                policy_name=policy_name,
                policy_content=policy_content,
                risk_title=risk_title,
                risk_description=risk_description
            )

            analyses.append(analysis)

        if not analyses:
            logger.warning("No policies were successfully analyzed")
            return []

        analyses.sort(key=lambda x: x.score, reverse=True)
        logger.info(
            f"Analysis complete. Returning top {top_n} policies out of {len(analyses)}")

        return analyses[:top_n]
