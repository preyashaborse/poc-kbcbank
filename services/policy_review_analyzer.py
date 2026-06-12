import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from langchain_community.document_loaders import PyPDFLoader
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

SYSTEM_PROMPT = """You are an AI Policy Scan Engine integrated into MetricStream Policy Management.

You are reviewing a primary policy draft against:

1. Referenced Global Policies
2. Referenced Local Policies
3. Linked Controls
4. Linked Risks

Your purpose is to identify:

- CONFLICT
- INCONSISTENCY
- BLIND SPOT
- CONTROLS & RISKS

Definitions:

CONFLICT
Two provisions that cannot both be true simultaneously.
Severity = Blocking.

Detect:
- Threshold mismatches
- Approval mismatches
- Numerical conflicts
- Global vs Local hierarchy violations
- Contradictory requirements

INCONSISTENCY
Statements that do not directly conflict but create ambiguity or operational confusion.
Severity = Non-Blocking.

Detect:
- Different terminology
- Undefined threshold gaps
- Ambiguous ownership
- Timing dependencies
- Restatement of Global policy without local specificity

BLIND SPOT
Material topics absent from the policy.

Severity = Advisory.

Detect:
- Risk not addressed in policy
- Control not supported by policy text
- Regulatory obligation missing
- Parent policy requirement missing where local supplement is required

CONTROLS & RISKS

Detect:
- Controls affected by conflicts
- Controls affected by inconsistencies
- Risks with no policy coverage
- Risks with no control coverage
- Policy sections with no mapped controls

Hierarchy Rules:

- Global Policy is authoritative baseline.
- Local Policy may be more restrictive.
- Local Policy may not be less restrictive.
- If Local is less restrictive than Global, classify as CONFLICT.
- If Local simply repeats Global with no additional specificity, classify as INCONSISTENCY.
- If a topic exists only in Global, do not automatically flag it.
- Flag only if local regulatory context requires a local supplement.

For every finding provide:

ID
Type
Severity
Title
Source A
Source B
Issue
Proposed Resolution
Confidence
Status

Status must always be:

Awaiting SME

Use exact document sections and exact excerpts from provided documents.

Do not invent content.

Do not approve policies.

Do not publish policies.

Produce output as valid JSON only."""


class _LLMFindingSource(BaseModel):
    document_id: str = ""
    version: str = ""
    section: str = ""
    excerpt: str = ""


class _LLMFinding(BaseModel):
    id: str
    type: str
    severity: str
    title: str
    source_a: _LLMFindingSource
    source_b: _LLMFindingSource | None = None
    issue: str
    proposed_resolution: str
    confidence: float = Field(ge=0, le=100)
    status: str = "Awaiting SME"


class _LLMReport(BaseModel):
    findings: list[_LLMFinding] = []
    overall_confidence: float | None = Field(default=None, ge=0, le=100)


class ResolvedReference(BaseModel):
    document_id: str
    version: str = ""
    title: str = ""
    content: str = ""
    status: str = "resolved"
    url: str = ""


class PolicyReviewAnalyzer:
    CONFIDENCE_DEDUCTION_UNRESOLVED = 10

    def __init__(self, policies_folder: str = "Files/policies"):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.error("OPENAI_API_KEY not found in environment variables")
            raise ValueError("OPENAI_API_KEY not found in environment variables")

        self.policies_folder = Path(policies_folder)
        self.llm = ChatOpenAI(model="gpt-4o", temperature=0.2, api_key=api_key)
        self.parser = JsonOutputParser(pydantic_object=_LLMReport)
        logger.info("PolicyReviewAnalyzer initialized for consistency analysis")

    def _extract_document_id_and_version(self, template: str) -> tuple[str, str]:
        doc_id = "POL-UNKNOWN"
        version = "1.0"

        patterns = [
            r"(POL-[A-Z0-9]+)\s*[—–-].*?[—–-]\s*v([\d.]+)",
            r"(POL-[A-Z0-9]+).*?v([\d.]+)",
            r"([A-Z]{2,}-[A-Z0-9]+)\s*[—–-].*?[—–-]\s*v([\d.]+)",
            r"([A-Z]{2,}-[A-Z0-9]+).*?v([\d.]+)",
            r"(POL-[A-Z0-9]+)",
            r"([A-Z]{2,}-[A-Z0-9]+)",
            r"v([\d.]+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, template, re.IGNORECASE)
            if not match:
                continue
            groups = match.groups()
            if len(groups) == 2:
                doc_id, version = groups[0].upper(), groups[1]
                break
            if len(groups) == 1:
                if "v" in pattern.lower():
                    version = groups[0]
                else:
                    doc_id = groups[0].upper()

        if not version.startswith("v"):
            version = f"v{version}"

        return doc_id, version

    def _extract_primary_title(self, template: str, document_name: str) -> str:
        header_match = re.search(
            r"^[A-Z0-9]+-[A-Z0-9]+\s*[—–-]\s*(.+?)\s*[—–-]\s*v",
            template.strip(),
            re.MULTILINE | re.IGNORECASE,
        )
        if header_match:
            return header_match.group(1).strip()
        return document_name

    def _extract_ref_from_url(self, url: str) -> tuple[str, str]:
        match = re.search(r"(POL-[A-Z0-9]+)-v([\d.]+)", url, re.IGNORECASE)
        if match:
            return match.group(1).upper(), f"v{match.group(2)}"

        match = re.search(r"(POL-[A-Z0-9]+)", url, re.IGNORECASE)
        if match:
            return match.group(1).upper(), ""

        return "POL-UNKNOWN", ""

    def _normalize_id_for_filename(self, document_id: str) -> str:
        return document_id.upper().replace("-", "_")

    def _find_policy_pdf(self, document_id: str) -> Path | None:
        if not self.policies_folder.exists():
            logger.warning(f"Policies folder not found: {self.policies_folder}")
            return None

        normalized = self._normalize_id_for_filename(document_id)
        candidates: list[Path] = []

        for pdf in self.policies_folder.glob("*.pdf"):
            stem_normalized = pdf.stem.upper().replace("-", "_")
            if stem_normalized.startswith(normalized) or normalized in stem_normalized:
                candidates.append(pdf)

        if not candidates:
            logger.warning(f"No PDF found for document_id {document_id} in {self.policies_folder}")
            return None

        candidates.sort(key=lambda p: p.name)
        logger.info(f"Resolved {document_id} to PDF: {candidates[0].name}")
        return candidates[0]

    def _load_pdf_text(self, policy_path: Path) -> str:
        loader = PyPDFLoader(str(policy_path))
        pages = loader.load()
        content = "\n".join(page.page_content for page in pages)
        logger.info(f"Loaded {len(pages)} pages from {policy_path.name}")
        return content

    def _extract_title_from_pdf_filename(self, path: Path, document_id: str) -> str:
        stem = path.stem.replace("_", " ")
        prefix = self._normalize_id_for_filename(document_id).replace("_", " ")
        if stem.upper().startswith(prefix):
            remainder = stem[len(prefix):].strip()
            if remainder:
                return remainder
        return stem

    def _resolve_references(self, references: list[dict]) -> list[ResolvedReference]:
        resolved: list[ResolvedReference] = []

        for ref in references:
            url = ref.get("url", "")
            document_id, version = self._extract_ref_from_url(url)
            pdf_path = self._find_policy_pdf(document_id)

            if not pdf_path:
                resolved.append(
                    ResolvedReference(
                        document_id=document_id,
                        version=version,
                        status="UNRESOLVED",
                        url=url,
                    )
                )
                continue

            content = self._load_pdf_text(pdf_path)
            title = self._extract_title_from_pdf_filename(pdf_path, document_id)
            doc_version, _ = self._extract_document_id_and_version(content)
            if doc_version and doc_version != "v1.0":
                version = doc_version

            resolved.append(
                ResolvedReference(
                    document_id=document_id,
                    version=version,
                    title=title,
                    content=content,
                    status="resolved",
                    url=url,
                )
            )

        return resolved

    def _build_analysis_context(
        self,
        policy_data: dict,
        resolved_refs: list[ResolvedReference],
    ) -> dict:
        return {
            "primary_policy": policy_data.get("template", ""),
            "references": [
                {
                    "document_id": ref.document_id,
                    "version": ref.version,
                    "title": ref.title,
                    "content": ref.content,
                    "status": ref.status,
                }
                for ref in resolved_refs
                if ref.status == "resolved"
            ],
            "controls": policy_data.get("controls", []),
            "related_risks": policy_data.get("relatedRisks", []),
        }

    def _format_reference_block(self, resolved_refs: list[ResolvedReference]) -> str:
        blocks = []
        for ref in resolved_refs:
            if ref.status != "resolved":
                blocks.append(
                    f"REFERENCE {ref.document_id} {ref.version} — STATUS: UNRESOLVED (URL: {ref.url})"
                )
                continue
            blocks.append(
                f"REFERENCE POLICY: {ref.document_id} {ref.version}\n"
                f"TITLE: {ref.title}\n"
                f"CONTENT:\n{ref.content[:12000]}"
            )
        return "\n\n---\n\n".join(blocks) if blocks else "No referenced policies provided."

    async def _run_llm_analysis(
        self,
        policy_data: dict,
        resolved_refs: list[ResolvedReference],
        unresolved_count: int,
    ) -> _LLMReport:
        primary_id, primary_version = self._extract_document_id_and_version(
            policy_data.get("template", "")
        )
        primary_title = self._extract_primary_title(
            policy_data.get("template", ""),
            policy_data.get("documentName", ""),
        )

        controls = policy_data.get("controls", [])
        risks = policy_data.get("relatedRisks", [])

        user_content = f"""Analyze the primary local policy against referenced global policies, controls, and risks.

PRIMARY LOCAL POLICY:
Document ID: {primary_id}
Version: {primary_version}
Title: {primary_title}

{policy_data.get("template", "")[:12000]}

REFERENCED POLICIES:
{self._format_reference_block(resolved_refs)}

LINKED CONTROLS:
{chr(10).join(controls) if controls else "None provided."}

LINKED RISKS:
{chr(10).join(risks) if risks else "None provided."}

Unresolved reference count: {unresolved_count}

Return JSON with:
- findings: array of findings (types: CONFLICT, INCONSISTENCY, BLIND SPOT, CONTROLS & RISKS)
- overall_confidence: 0-100 score for the full scan

{self.parser.get_format_instructions()}"""

        response = await self.llm.ainvoke(
            [
                SystemMessage(content=SYSTEM_PROMPT),
                HumanMessage(content=user_content),
            ]
        )

        raw = response.content if isinstance(response.content, str) else str(response.content)
        return self._parse_llm_report(raw)

    def _parse_llm_report(self, raw: str) -> _LLMReport:
        """Parse LLM JSON output into _LLMReport (parser returns dict, not a model)."""
        try:
            parsed = self.parser.parse(raw)
            if isinstance(parsed, _LLMReport):
                return parsed
            return _LLMReport.model_validate(parsed)
        except (ValidationError, json.JSONDecodeError, TypeError) as e:
            logger.warning(f"Structured parse failed, attempting JSON extraction: {e}")
            json_match = re.search(r"\{.*\}", raw, re.DOTALL)
            if not json_match:
                raise ValueError("LLM did not return valid JSON") from e
            return _LLMReport.model_validate(json.loads(json_match.group()))

    def _count_findings_by_type(self, findings: list[_LLMFinding]) -> dict[str, int]:
        counts = {
            "CONFLICT": 0,
            "INCONSISTENCY": 0,
            "BLIND SPOT": 0,
            "CONTROLS & RISKS": 0,
        }
        for finding in findings:
            normalized = finding.type.strip().upper()
            if normalized in counts:
                counts[normalized] += 1
            elif "CONTROL" in normalized or "RISK" in normalized:
                counts["CONTROLS & RISKS"] += 1
        return counts

    def _compute_overall_confidence(
        self,
        llm_report: _LLMReport,
        findings: list[_LLMFinding],
        unresolved_count: int,
    ) -> float:
        if llm_report.overall_confidence is not None:
            base = float(llm_report.overall_confidence)
        elif findings:
            base = sum(f.confidence for f in findings) / len(findings)
        else:
            base = 100.0

        deduction = unresolved_count * self.CONFIDENCE_DEDUCTION_UNRESOLVED
        return max(0.0, min(100.0, base - deduction))

    def _normalize_finding(self, finding: _LLMFinding) -> dict:
        source_b = None
        if finding.source_b and any(
            [
                finding.source_b.document_id,
                finding.source_b.section,
                finding.source_b.excerpt,
            ]
        ):
            source_b = {
                "document_id": finding.source_b.document_id,
                "version": finding.source_b.version,
                "section": finding.source_b.section,
                "excerpt": finding.source_b.excerpt,
            }

        return {
            "id": finding.id,
            "type": finding.type,
            "severity": finding.severity,
            "title": finding.title,
            "source_a": {
                "document_id": finding.source_a.document_id,
                "version": finding.source_a.version,
                "section": finding.source_a.section,
                "excerpt": finding.source_a.excerpt,
            },
            "source_b": source_b,
            "issue": finding.issue,
            "proposed_resolution": finding.proposed_resolution,
            "confidence": finding.confidence,
            "status": "Awaiting SME",
        }

    async def analyze_consistency(self, policy_data: dict) -> dict:
        """Run UC 3.3 policy consistency analysis (local + referenced global + controls + risks)."""
        document_name = policy_data.get("documentName", "")
        template = policy_data.get("template", "")

        if not template:
            return {
                "success": False,
                "message": "Policy template is required",
                "report": None,
            }

        logger.info(f"Starting consistency analysis for: {document_name}")

        primary_id, primary_version = self._extract_document_id_and_version(template)
        primary_title = self._extract_primary_title(template, document_name)

        resolved_refs = self._resolve_references(policy_data.get("references", []))
        unresolved_count = sum(1 for ref in resolved_refs if ref.status == "UNRESOLVED")

        context = self._build_analysis_context(policy_data, resolved_refs)
        logger.info(
            f"Analysis context built: {len(context['references'])} resolved references, "
            f"{len(context['controls'])} controls, {len(context['related_risks'])} risks"
        )

        llm_report = await self._run_llm_analysis(policy_data, resolved_refs, unresolved_count)

        normalized_findings = [self._normalize_finding(f) for f in llm_report.findings]
        type_counts = self._count_findings_by_type(llm_report.findings)

        blocking_issues = sum(
            1
            for f in llm_report.findings
            if f.type.strip().upper() == "CONFLICT" and f.severity.strip().lower() == "blocking"
        )

        overall_confidence = self._compute_overall_confidence(
            llm_report, llm_report.findings, unresolved_count
        )

        report = {
            "scan_date": datetime.now(timezone.utc),
            "primary_policy": {
                "policy_id": primary_id,
                "title": primary_title,
                "version": primary_version,
            },
            "references_fetched": [
                {
                    "document_id": ref.document_id,
                    "version": ref.version,
                    "status": ref.status.lower() if ref.status == "resolved" else ref.status,
                }
                for ref in resolved_refs
            ],
            "summary": {
                "conflicts": type_counts["CONFLICT"],
                "inconsistencies": type_counts["INCONSISTENCY"],
                "blind_spots": type_counts["BLIND SPOT"],
                "controls_and_risks": type_counts["CONTROLS & RISKS"],
            },
            "overall_confidence": round(overall_confidence, 1),
            "publication_readiness": {
                "status": "NOT READY" if blocking_issues > 0 else "READY",
                "blocking_issues": blocking_issues,
            },
            "findings": normalized_findings,
        }

        logger.info(
            f"Consistency analysis completed for {document_name}: "
            f"{len(normalized_findings)} findings, readiness={report['publication_readiness']['status']}"
        )

        return {"success": True, "report": report}
