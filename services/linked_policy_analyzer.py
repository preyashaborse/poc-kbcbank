import json
import logging
import os
from typing import List, Dict

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field, ValidationError

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """You are a regulatory compliance and policy mapping expert.

You are given:
1. The content of a regulatory change.
2. A list of compliance obligations extracted from that regulation.
3. A catalogue of the organization's existing internal policies (with metadata).

Your task is to determine which existing policies are most impacted by, or linked to, this regulatory change and its obligations, and to RANK them by relevance.

Instructions:

1. Compare the regulatory content and the obligations against each policy in the catalogue.
2. For each policy that is relevant, assess how strongly it is linked to the regulation and obligations based on its title, business line, owner, and risk level.
3. Assign a relevance_score from 0 to 100:
   * 81-100: Directly governs the obligations; primary policy that must be updated.
   * 61-80: Strongly related; significant overlap with the obligations.
   * 41-60: Moderately related; some obligations touch this policy.
   * 21-40: Tangentially related; minor overlap.
   * 0-20: Barely or not related.
4. Only include policies with a meaningful link (relevance_score >= 21). Omit clearly irrelevant policies.
5. For each ranked policy, list the obligation_ids that map to it (matched_obligations).
6. Provide a concise, specific rationale referencing the obligations and the policy's scope.
7. Rank the output from highest to lowest relevance_score.

Use ONLY the information provided. Do not invent policies that are not in the catalogue.

Return ONLY valid JSON in the following format:

{
"ranked_policies": [
{
"policy_id": "POL-007",
"policy_title": "AI Governance & Model Risk Policy",
"relevance_score": 92,
"rationale": "Directly governs AI model risk controls required by the obligations.",
"matched_obligations": ["OBL-001", "OBL-003"]
}
]
}
"""


class RankedPolicy(BaseModel):
    policy_id: str = Field(description="Policy identifier, e.g. POL-007")
    policy_title: str = Field(description="Title of the policy")
    relevance_score: float = Field(description="Relevance score from 0 to 100", ge=0, le=100)
    rationale: str = Field(description="Why this policy is linked to the regulation")
    matched_obligations: List[str] = Field(
        default_factory=list, description="Obligation ids mapped to this policy"
    )


class LinkedPolicyResult(BaseModel):
    ranked_policies: List[RankedPolicy]


class LinkedPolicyAnalyzer:
    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.error("OPENAI_API_KEY not found in environment variables")
            raise ValueError("OPENAI_API_KEY not found in environment variables")

        try:
            self.llm = ChatOpenAI(model="gpt-4o", temperature=0.2, api_key=api_key)
            self.parser = JsonOutputParser(pydantic_object=LinkedPolicyResult)
            logger.info("LinkedPolicyAnalyzer initialized")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}", exc_info=True)
            raise

    def rank_policies(
        self,
        regulatory_content: str,
        obligations: List[Dict],
        policies: List[Dict],
    ) -> List[RankedPolicy]:
        """Rank existing policies by their relevance to a regulatory change and its obligations."""
        if not policies:
            logger.warning("No policies provided to rank")
            return []

        obligations_text = json.dumps(obligations, indent=2, ensure_ascii=False)
        policies_text = json.dumps(policies, indent=2, ensure_ascii=False)

        user_content = (
            f"Regulatory Content:\n{regulatory_content[:60000]}\n\n"
            f"Extracted Obligations:\n{obligations_text}\n\n"
            f"Existing Policy Catalogue:\n{policies_text}\n\n"
            "Rank the policies most linked to this regulation and return ONLY the JSON object."
        )

        try:
            logger.info(f"Ranking {len(policies)} policies against regulatory change")
            response = self.llm.invoke([
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=user_content),
            ])

            parsed = self.parser.parse(response.content)
            result = LinkedPolicyResult(**parsed)
            ranked = sorted(
                result.ranked_policies, key=lambda p: p.relevance_score, reverse=True
            )
            logger.info(f"Ranked {len(ranked)} linked policies")
            return ranked
        except ValidationError as e:
            logger.error(f"Validation error ranking policies: {e}", exc_info=True)
            raise ValueError(f"Failed to parse ranked policies from LLM response: {e}")
        except Exception as e:
            logger.error(f"Error ranking policies: {e}", exc_info=True)
            raise
