import logging
import os
from typing import List

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


SYSTEM_PROMPT = """You are a regulatory compliance expert.

Your task is to analyze the regulatory content provided below and extract all explicit and implicit compliance obligations.

Instructions:

1. Identify every obligation, requirement, mandate, control expectation, governance expectation, reporting requirement, documentation requirement, risk management requirement, monitoring requirement, oversight requirement, audit requirement, or compliance activity mentioned in the content.

2. Rewrite each obligation as a clear, actionable statement beginning with a verb such as:

   * Establish
   * Maintain
   * Implement
   * Monitor
   * Document
   * Perform
   * Assess
   * Review
   * Report
   * Ensure

3. Do not summarize the regulation.
   Extract obligations only.

4. If multiple requirements are mentioned in a single paragraph, split them into separate obligations.

5. For each obligation, determine:

   * obligation_id
   * obligation_text
   * obligation_category
   * priority (High / Medium / Low)
   * rationale

6. Use only the information present in the regulatory content.

Return ONLY valid JSON in the following format:

{
"obligations": [
{
"obligation_id": "OBL-001",
"obligation_text": "Establish and maintain a quality management system for high-risk AI systems.",
"obligation_category": "Governance",
"priority": "High",
"rationale": "Required under Article 17 of the AI Act."
}
]
}

Regulatory Content:

{{REGULATORY_CONTENT}}
"""


class Obligation(BaseModel):
    obligation_id: str = Field(description="Unique obligation identifier, e.g. OBL-001")
    obligation_text: str = Field(description="Actionable obligation statement")
    obligation_category: str = Field(description="Category of the obligation")
    priority: str = Field(description="Priority: High, Medium, or Low")
    rationale: str = Field(description="Why this obligation exists, based on the content")


class ObligationExtractionResult(BaseModel):
    obligations: List[Obligation]


class ObligationExtractor:
    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.error("OPENAI_API_KEY not found in environment variables")
            raise ValueError("OPENAI_API_KEY not found in environment variables")

        try:
            self.llm = ChatOpenAI(model="gpt-4o", temperature=0.2, api_key=api_key)
            self.parser = JsonOutputParser(pydantic_object=ObligationExtractionResult)
            logger.info("ObligationExtractor initialized")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}", exc_info=True)
            raise

    def extract_obligations(self, regulatory_content: str) -> List[Obligation]:
        """Extract compliance obligations from regulatory content using an LLM."""
        if not regulatory_content or not regulatory_content.strip():
            logger.warning("No regulatory content provided for obligation extraction")
            raise ValueError("Regulatory content is empty")

        system_content = SYSTEM_PROMPT.replace(
            "{{REGULATORY_CONTENT}}", regulatory_content[:100000]
        )

        try:
            logger.info("Extracting obligations from regulatory content")
            response = self.llm.invoke([
                SystemMessage(content=system_content),
                HumanMessage(content="Extract all obligations and return ONLY the JSON object."),
            ])

            parsed = self.parser.parse(response.content)
            result = ObligationExtractionResult(**parsed)
            logger.info(f"Extracted {len(result.obligations)} obligations")
            return result.obligations
        except ValidationError as e:
            logger.error(f"Validation error parsing obligations: {e}", exc_info=True)
            raise ValueError(f"Failed to parse obligations from LLM response: {e}")
        except Exception as e:
            logger.error(f"Error extracting obligations: {e}", exc_info=True)
            raise
