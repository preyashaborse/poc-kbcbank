import logging
import os
import re
from datetime import datetime
from typing import Optional
import httpx
from dotenv import load_dotenv
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


class PolicyFinding(BaseModel):
    finding_id: str
    finding_type: str
    severity: str
    title: str
    description: str
    affected_sections: list[str]
    cited_excerpts: list[str]
    confidence_score: float
    confidence_reason: str
    cross_document_refs: list[str] = []
    remediation_notes: str = ""


class ControlFinding(BaseModel):
    control_id: str
    control_text: str
    status: str
    linked_findings: list[str]
    notes: str


class RiskFinding(BaseModel):
    risk_id: str
    risk_text: str
    status: str
    policy_coverage: str
    linked_findings: list[str]
    notes: str


class PolicyReviewAnalyzer:
    SYSTEM_PROMPT = """You are an AI Policy Scan Engine integrated into MetricStream Policy Management.
 
You receive a policy object containing: policy text (template), controls, relatedRisks, and references (URLs to parent or related policies).
 
For each reference URL: fetch and analyse the document. If unreachable, note it and mark all related findings as [UNVERIFIED]. If the fetched document's version or date differs from the version cited in the policy metadata, flag the discrepancy, reduce confidence by 10 points, and apply findings based on the fetched version noting the version delta in each affected finding. If a reference URL resolves to a document that itself references the primary policy under scan, do not fetch it recursively — note the circular reference and mark related findings as [UNVERIFIED — CIRCULAR REFERENCE].
 
---
 
## YOUR JOB
 
Scan the policy and all fetched references. Produce a structured report using the finding schema below. Four finding types:
 
CONFLICT — Two provisions that cannot both be correct simultaneously. Severity: Blocking. Detect: numerical mismatches, hierarchy violations (local is less restrictive than global parent), contradictory rules for the same scenario across or within documents. Two provisions describe the same scenario if they would both apply to the same real-world transaction, event, or decision — determined by subject (same actor), object (same asset or action), and trigger condition (overlapping threshold or circumstance), not by identical wording.
 
INCONSISTENCY — Provisions that don't contradict but cause ambiguity or procedural confusion. Severity: Non-Blocking. Detect: undefined gaps between thresholds, same item named differently in different sections, timing dependencies that make a commitment impossible to honour simultaneously.
 
BLIND SPOT — A material topic absent from the policy where absence creates regulatory exposure or misalignment with stated commitments. Severity: Advisory. A topic qualifies only if at least one of the following is true: (a) it is required by a regulation cited in the policy's references; (b) it is addressed in a parent policy and local regulatory context warrants a local supplement; (c) the organisation has a documented public commitment (CSRD, AI governance framework, privacy policy) that this policy's subject matter would be expected to operationalise; or (d) it is addressed in linked controls or risks but has no corresponding policy section. Detect: regulations or cross-referenced policies mentioned with no corresponding mechanism; stated commitments with no operational provision.
 
CONTROLS & RISKS — After the above findings: flag any control linked to a section with a Conflict or Inconsistency (may be unenforceable); flag any risk with no policy section and no control addressing it (unmitigated); flag any policy section with no mapped control (advisory gap).
 
---
 
## FINDING SCHEMA
 
Each finding must use this exact structure:
 
  ID: [C/I/B/CR]-[NNN]
  Type: [CONFLICT | INCONSISTENCY | BLIND SPOT | CONTROLS & RISKS]
  Severity: [Blocking | Non-Blocking | Advisory]
  Title: [≤12 words]
  Source A: [Document ID, version, section, verbatim excerpt ≤30 words]
  Source B: [Document ID, version, section, verbatim excerpt ≤30 words — or "N/A" for blind spots]
  Issue: [2–4 sentences, no recommendations]
  Proposed Resolution: [Option A / Option B for policy judgement calls; single recommendation for factual fixes only]
  Confidence: [0–100]%
  Status: Awaiting SME
 
---
 
## HIERARCHY RULE
 
When a reference URL resolves to a parent/global policy:
- Local MORE restrictive than Global → valid.
- Local LESS restrictive than Global → CONFLICT (Blocking).
- Local restates Global without adding specificity → INCONSISTENCY (Non-Blocking).
- Topic absent from BOTH → Blind Spot candidate.
- Topic in Global, absent from Local → not a gap (Global governs); flag only if local regulatory context warrants a local supplement.
 
Always cite both document IDs and versions in cross-document findings.
 
---
 
## ONE EXAMPLE
 
Input:
  Local §3.1: "Pre-approval required for trips exceeding EUR 1,000"
  Global §8.2 (from fetched reference): "Expense claims exceeding EUR 800 must include a pre-approval copy"
  Control: "CTR-001 — Automated block at EUR 800 threshold"
 
Findings produced:
  ID: C-001
  Type: CONFLICT
  Severity: Blocking
  Title: Pre-approval threshold contradicts expense documentation requirement
  Source A: POL-T002 v2.1, §3.1 — "Pre-approval required for trips exceeding EUR 1,000"
  Source B: POL-T001 v1.2, §8.2 — "Expense claims exceeding EUR 800 must include a pre-approval copy"
  Issue: §3.1 triggers pre-approval at EUR 1,000 but §8.2 requires a pre-approval document for claims above EUR 800. A trip costing EUR 900 requires the document but has no approval obligation to generate it. The two thresholds cannot coexist without creating an unenforceable documentation requirement for the EUR 800–999 band.
  Proposed Resolution: Option A — Align both thresholds to EUR 1,000 and add a retrospective confirmation process for the EUR 800–999 band. Option B — Align both thresholds to EUR 800 (more conservative). Group CFO to confirm which reflects current risk appetite.
  Confidence: 94%
  Status: Awaiting SME
 
  ID: CR-001
  Type: CONTROLS & RISKS
  Severity: Non-Blocking
  Title: CTR-001 calibrated to unresolved conflict threshold
  Source A: CTR-001 — "Automated block at EUR 800 threshold"
  Source B: C-001 (above)
  Issue: CTR-001 enforces a EUR 800 threshold that has no confirmed policy backing until C-001 is resolved. The control is partially unenforceable for the EUR 800–999 band.
  Proposed Resolution: Suspend threshold configuration change until C-001 is resolved. Update CTR-001 parameter to match the confirmed threshold.
  Confidence: 94%
  Status: Awaiting SME
 
---
 
## REPORT HEADER (required)
 
The report must open with:
  Scan Date: [timestamp]
  Primary Policy: [ID, title, version]
  References Fetched: [list with status — resolved / unresolved / circular]
  Total Findings: [n Conflicts | n Inconsistencies | n Blind Spots | n Controls & Risks]
  Overall Confidence: [0–100]%  |  Reason: [one sentence]  |  Reduction factors: [list]
  Publication Readiness: [READY | NOT READY — [n] blocking issues]
 
---
 
## CONSTRAINTS
 
- Cite exact section numbers and verbatim excerpts (≤30 words) for every finding.
- Do not invent policy content not present in the inputs.
- Do not recommend one resolution option over another on policy judgement calls; reserve single recommendations for factual fixes only (naming errors, arithmetic, citation corrections).
- The AI does not approve or publish policies. The Policy Owner retains full authority.
- All findings default to Status: Awaiting SME. Do not change this field.
- Confidence score must appear in the report header as a structured field, not embedded in narrative text. Deductions: −10 per unresolved reference URL; −10 if version metadata is missing from any scanned document; −5 if policy scope is ambiguous; −15 if no linked controls or risks are provided."""

    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            logger.error("OPENAI_API_KEY not found in environment variables")
            raise ValueError("OPENAI_API_KEY not found in environment variables")

        try:
            self.llm = ChatOpenAI(model="gpt-4o", temperature=0.2, api_key=api_key)
            logger.info("PolicyReviewAnalyzer initialized with system prompt")
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}", exc_info=True)
            raise

    async def fetch_reference_document(self, url: str) -> tuple[str, bool]:
        """Fetch and extract text from a reference URL."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url)
                response.raise_for_status()
                logger.info(f"Successfully fetched reference document: {url}")
                return response.text[:8000], True
        except Exception as e:
            logger.warning(f"Failed to fetch reference document {url}: {e}")
            return "", False

    def _extract_document_id_and_version(self, template: str) -> tuple[str, str]:
        """Extract document ID and version from policy template dynamically."""
        doc_id = "POL-UNKNOWN"
        version = "1.0"
        
        patterns = [
            r'(POL-[A-Z0-9]+)\s*[—–-].*?[—–-]\s*v([\d.]+)',
            r'(POL-[A-Z0-9]+).*?v([\d.]+)',
            r'([A-Z]{2,}-[A-Z0-9]+)\s*[—–-].*?[—–-]\s*v([\d.]+)',
            r'([A-Z]{2,}-[A-Z0-9]+).*?v([\d.]+)',
            r'(POL-[A-Z0-9]+)',
            r'([A-Z]{2,}-[A-Z0-9]+)',
            r'v([\d.]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, template, re.IGNORECASE)
            if match:
                groups = match.groups()
                if len(groups) == 2:
                    doc_id, version = groups[0].upper(), groups[1]
                    break
                elif len(groups) == 1:
                    if 'v' in pattern.lower():
                        version = groups[0]
                    else:
                        doc_id = groups[0].upper()
        
        return doc_id, version

    def _extract_sections(self, template: str) -> dict[str, str]:
        """Extract all sections from policy template dynamically, handling various formats."""
        sections = {}
        
        section_patterns = [
            (r'(§\d+\.?\d*)\s*[—–-]?\s*([^\n]+)\n((?:(?!§\d)[^\n])*)', 'symbol'),
            (r'(\d+\.\d+)\s+([^\n]+)\n((?:(?!\d+\.\d+)[^\n])*)', 'decimal'),
            (r'(Section\s+\d+\.?\d*)\s*[—–-]?\s*([^\n]+)\n((?:(?!Section\s+\d)[^\n])*)', 'word'),
            (r'(\d+\.0)\s+([^\n]+)\n((?:(?!\d+\.0)[^\n])*)', 'major'),
            (r'(Part\s+[IVX]+)\s*[—–-]?\s*([^\n]+)\n((?:(?!Part\s+[IVX]+)[^\n])*)', 'roman'),
        ]
        
        for pattern, pattern_type in section_patterns:
            matches = list(re.finditer(pattern, template, re.MULTILINE | re.IGNORECASE))
            if matches:
                logger.info(f"Detected section format: {pattern_type}")
                for match in matches:
                    section_num = match.group(1).strip()
                    section_title = match.group(2).strip() if len(match.groups()) >= 2 else ""
                    section_content = match.group(3).strip() if len(match.groups()) >= 3 else ""
                    
                    if section_content:
                        sections[section_num] = {
                            'title': section_title,
                            'content': section_content
                        }
                
                if sections:
                    break
        
        if not sections:
            lines = template.split('\n')
            current_section = None
            current_content = []
            
            for line in lines:
                if re.match(r'^[0-9§IVX]', line.strip()) and len(line.strip()) > 1:
                    if current_section:
                        sections[current_section['num']] = {
                            'title': current_section['title'],
                            'content': '\n'.join(current_content).strip()
                        }
                    
                    parts = line.split(':', 1)
                    current_section = {
                        'num': parts[0].strip(),
                        'title': parts[1].strip() if len(parts) > 1 else ''
                    }
                    current_content = []
                elif current_section:
                    current_content.append(line)
            
            if current_section:
                sections[current_section['num']] = {
                    'title': current_section['title'],
                    'content': '\n'.join(current_content).strip()
                }
        
        if not sections:
            sections['FULL_TEMPLATE'] = {
                'title': 'Full Policy Document',
                'content': template
            }
            logger.warning("Could not parse sections; treating entire template as single section")
        
        return sections

    async def _detect_conflicts(self, sections: dict, references_content: list[tuple[str, bool]]) -> list[PolicyFinding]:
        """Detect CONFLICT findings (blocking severity) - provisions that cannot coexist."""
        findings = []
        finding_counter = 1

        for section_num, section_data in sections.items():
            content = section_data['content']
            section_title = section_data['title']
            
            threshold_matches = re.findall(r'EUR\s+([\d,]+)', content)
            approval_context = 'pre-approval' in content.lower() or 'approval' in content.lower()
            
            if threshold_matches and approval_context:
                for ref_idx, (ref_content, is_verified) in enumerate(references_content):
                    ref_thresholds = re.findall(r'EUR\s+([\d,]+)', ref_content)
                    ref_approval_context = 'pre-approval' in ref_content.lower() or 'approval' in ref_content.lower()
                    
                    if ref_thresholds and ref_approval_context:
                        for local_threshold in threshold_matches:
                            for ref_threshold in ref_thresholds:
                                local_val = int(local_threshold.replace(',', ''))
                                ref_val = int(ref_threshold.replace(',', ''))
                                
                                if local_val > ref_val:
                                    mid_point = (local_val + ref_val) // 2
                                    description = f"§{section_num} requires pre-approval at EUR {local_threshold} but referenced global policy requires pre-approval at EUR {ref_threshold}. A transaction at EUR {mid_point} would require a pre-approval document (per global policy) but would not trigger the approval obligation (per local policy). These two thresholds cannot coexist."
                                    
                                    cited_excerpts = [
                                        f"Local §{section_num}: {content[:150]}",
                                        f"Global Policy: {ref_content[:150]}"
                                    ]
                                    
                                    confidence_score, confidence_reason = await self._score_finding_confidence(
                                        "CONFLICT",
                                        description,
                                        cited_excerpts
                                    )
                                    
                                    finding = PolicyFinding(
                                        finding_id=f"C-{finding_counter:03d}",
                                        finding_type="CONFLICT",
                                        severity="Blocking",
                                        title=f"Threshold Conflict in §{section_num}: Local ({section_title}) vs Global Policy",
                                        description=description,
                                        affected_sections=[section_num],
                                        cited_excerpts=cited_excerpts,
                                        confidence_score=confidence_score,
                                        confidence_reason=confidence_reason,
                                        cross_document_refs=[f"Reference {ref_idx + 1}"],
                                        remediation_notes="Policy owner must align approval thresholds. Local threshold must not exceed global threshold."
                                    )
                                    findings.append(finding)
                                    finding_counter += 1

        return findings

    async def _detect_inconsistencies(self, sections: dict, references_content: list[tuple[str, bool]]) -> list[PolicyFinding]:
        """Detect INCONSISTENCY findings (non-blocking severity) - ambiguity or procedural confusion."""
        findings = []
        finding_counter = 1

        for section_num, section_data in sections.items():
            content = section_data['content']
            section_title = section_data['title']
            
            if 'submission' in content.lower() or 'deadline' in content.lower() or 'within' in content.lower():
                day_matches = re.findall(r'(\d+)\s+(?:calendar\s+)?days?', content)
                if day_matches:
                    for ref_idx, (ref_content, is_verified) in enumerate(references_content):
                        ref_day_matches = re.findall(r'(\d+)\s+(?:calendar\s+)?days?', ref_content)
                        for local_days in day_matches:
                            for ref_days in ref_day_matches:
                                if local_days != ref_days and int(local_days) < int(ref_days):
                                    description = f"§{section_num} requires submission within {local_days} days, but referenced policy allows {ref_days} days. This creates a timing dependency where the local deadline is stricter than the global standard, potentially causing procedural confusion for employees who must meet the earlier deadline."
                                    
                                    cited_excerpts = [
                                        f"Local §{section_num}: {content[:150]}",
                                        f"Global Policy: {ref_content[:150]}"
                                    ]
                                    
                                    confidence_score, confidence_reason = await self._score_finding_confidence(
                                        "INCONSISTENCY",
                                        description,
                                        cited_excerpts
                                    )
                                    
                                    finding = PolicyFinding(
                                        finding_id=f"I-{finding_counter:03d}",
                                        finding_type="INCONSISTENCY",
                                        severity="Non-Blocking",
                                        title=f"Timing Dependency Gap in §{section_num}: {section_title}",
                                        description=description,
                                        affected_sections=[section_num],
                                        cited_excerpts=cited_excerpts,
                                        confidence_score=confidence_score,
                                        confidence_reason=confidence_reason,
                                        cross_document_refs=[f"Reference {ref_idx + 1}"],
                                        remediation_notes="Policy owner should clarify whether local deadline overrides global deadline or if both apply."
                                    )
                                    findings.append(finding)
                                    finding_counter += 1
            
            if 'named' in content.lower() or 'called' in content.lower() or 'referred' in content.lower():
                term_matches = re.findall(r'(?:named|called|referred to as|known as)\s+["\']?([^"\'.,\n]+)["\']?', content, re.IGNORECASE)
                if term_matches:
                    for ref_idx, (ref_content, is_verified) in enumerate(references_content):
                        for term in term_matches:
                            if term.lower() not in ref_content.lower():
                                description = f"§{section_num} refers to '{term}' but this term does not appear in the referenced policy. This creates ambiguity about whether they refer to the same concept under different names."
                                
                                cited_excerpts = [f"Local §{section_num}: {content[:150]}"]
                                
                                confidence_score, confidence_reason = await self._score_finding_confidence(
                                    "INCONSISTENCY",
                                    description,
                                    cited_excerpts
                                )
                                
                                finding = PolicyFinding(
                                    finding_id=f"I-{finding_counter:03d}",
                                    finding_type="INCONSISTENCY",
                                    severity="Non-Blocking",
                                    title=f"Terminology Inconsistency in §{section_num}",
                                    description=description,
                                    affected_sections=[section_num],
                                    cited_excerpts=cited_excerpts,
                                    confidence_score=confidence_score,
                                    confidence_reason=confidence_reason,
                                    cross_document_refs=[f"Reference {ref_idx + 1}"],
                                    remediation_notes="Policy owner should verify whether '{term}' and referenced terms are synonymous."
                                )
                                findings.append(finding)
                                finding_counter += 1

        return findings

    async def _detect_blind_spots(self, sections: dict, controls: list[str], related_risks: list[str]) -> list[PolicyFinding]:
        """Detect BLIND_SPOT findings (advisory severity) - material topics absent from policy."""
        findings = []
        finding_counter = 1

        policy_text = " ".join([s['content'].lower() for s in sections.values()])
        controls_text = " ".join([c.lower() for c in controls])
        risks_text = " ".join([r.lower() for r in related_risks])

        regulatory_topics = {
            'tax': ['tax', 'withholding', 'fiscal', 'bedrijfsvoorheffing', 'précompte'],
            'gdpr': ['gdpr', 'data protection', 'personal data', 'privacy'],
            'compliance': ['compliance', 'regulatory', 'audit', 'governance'],
            'approval': ['approval', 'authorization', 'pre-approval', 'pre-authorization'],
            'audit': ['audit', 'audit trail', 'logging', 'tracking'],
            'exception': ['exception', 'waiver', 'deviation', 'override'],
        }

        for topic, keywords in regulatory_topics.items():
            topic_in_policy = any(kw in policy_text for kw in keywords)
            topic_in_controls = any(kw in controls_text for kw in keywords)
            topic_in_risks = any(kw in risks_text for kw in keywords)

            if topic_in_policy and not topic_in_controls:
                affected_sections = [
                    section_num for section_num, section_data in sections.items()
                    if any(kw in section_data['content'].lower() for kw in keywords)
                ]
                
                description = f"Policy mentions {topic} requirements (in sections {', '.join(affected_sections)}) but no control is defined to verify or enforce {topic} compliance. This creates regulatory exposure."
                cited_excerpts = [sections[s]['content'][:120] for s in affected_sections if s in sections]
                
                confidence_score, confidence_reason = await self._score_finding_confidence(
                    "BLIND_SPOT",
                    description,
                    cited_excerpts
                )
                
                finding = PolicyFinding(
                    finding_id=f"B-{finding_counter:03d}",
                    finding_type="BLIND_SPOT",
                    severity="Advisory",
                    title=f"No Control Mechanism for {topic.upper()} Compliance",
                    description=description,
                    affected_sections=affected_sections,
                    cited_excerpts=cited_excerpts,
                    confidence_score=confidence_score,
                    confidence_reason=confidence_reason,
                    remediation_notes=f"Policy owner should define a control to monitor and enforce {topic} compliance."
                )
                findings.append(finding)
                finding_counter += 1

            if topic_in_policy and not topic_in_risks:
                affected_sections = [
                    section_num for section_num, section_data in sections.items()
                    if any(kw in section_data['content'].lower() for kw in keywords)
                ]
                
                description = f"Policy addresses {topic} in sections {', '.join(affected_sections)}, but no corresponding risk is documented for {topic} non-compliance or failure. This gap may indicate incomplete risk assessment."
                cited_excerpts = [sections[s]['content'][:120] for s in affected_sections if s in sections]
                
                confidence_score, confidence_reason = await self._score_finding_confidence(
                    "BLIND_SPOT",
                    description,
                    cited_excerpts
                )
                
                finding = PolicyFinding(
                    finding_id=f"B-{finding_counter:03d}",
                    finding_type="BLIND_SPOT",
                    severity="Advisory",
                    title=f"No Risk Documented for {topic.upper()} Non-Compliance",
                    description=description,
                    affected_sections=affected_sections,
                    cited_excerpts=cited_excerpts,
                    confidence_score=confidence_score,
                    confidence_reason=confidence_reason,
                    remediation_notes=f"Policy owner should document risks associated with {topic} non-compliance."
                )
                findings.append(finding)
                finding_counter += 1

        if 'approval' in policy_text:
            approval_sections = [
                section_num for section_num, section_data in sections.items()
                if 'approval' in section_data['content'].lower()
            ]
            if approval_sections and not any('bypass' in r.lower() or 'unauthorized' in r.lower() for r in related_risks):
                description = f"Policy requires approval in sections {', '.join(approval_sections)}, but no risk is documented for approval workflow bypass, unauthorized approval, or approval circumvention. This creates unmitigated operational risk."
                cited_excerpts = [sections[s]['content'][:120] for s in approval_sections if s in sections]
                
                confidence_score, confidence_reason = await self._score_finding_confidence(
                    "BLIND_SPOT",
                    description,
                    cited_excerpts
                )
                
                finding = PolicyFinding(
                    finding_id=f"B-{finding_counter:03d}",
                    finding_type="BLIND_SPOT",
                    severity="Advisory",
                    title="Approval Bypass Risk Not Documented",
                    description=description,
                    affected_sections=approval_sections,
                    cited_excerpts=cited_excerpts,
                    confidence_score=confidence_score,
                    confidence_reason=confidence_reason,
                    remediation_notes="Policy owner should document risks related to approval workflow failures and define compensating controls."
                )
                findings.append(finding)
                finding_counter += 1

        return findings

    def _analyze_controls(self, controls: list[str], findings: list[PolicyFinding]) -> list[ControlFinding]:
        """Analyze control enforceability based on findings."""
        control_findings = []
        
        for idx, control in enumerate(controls):
            control_id = f"CTR-{idx + 1:03d}"
            linked_findings = []
            status = "Enforceable"
            
            for finding in findings:
                if finding.finding_type == "CONFLICT":
                    if any(threshold in control for threshold in re.findall(r'EUR\s+\d+', control)):
                        linked_findings.append(finding.finding_id)
                        status = "Partially Enforceable"
                elif finding.finding_type == "INCONSISTENCY":
                    if any(word in control.lower() for word in ['approval', 'submission', 'deadline']):
                        linked_findings.append(finding.finding_id)
                        if status == "Enforceable":
                            status = "Partially Enforceable"

            notes = f"Control {control_id} is {status.lower()}"
            if linked_findings:
                notes += f" due to findings: {', '.join(linked_findings)}"

            control_findings.append(ControlFinding(
                control_id=control_id,
                control_text=control,
                status=status,
                linked_findings=linked_findings,
                notes=notes
            ))

        return control_findings

    def _analyze_risks(self, related_risks: list[str], findings: list[PolicyFinding], sections: dict) -> list[RiskFinding]:
        """Analyze risk mitigation based on policy coverage."""
        risk_findings = []
        
        for idx, risk in enumerate(related_risks):
            risk_id = f"RTR-{idx + 1:03d}"
            linked_findings = []
            status = "Mitigated"
            policy_coverage = "Fully Covered"
            
            risk_lower = risk.lower()
            
            if 'unapproved' in risk_lower or 'approval' in risk_lower:
                if any('approval' in section_data['content'].lower() for section_data in sections.values()):
                    policy_coverage = "Fully Covered"
                else:
                    policy_coverage = "Uncovered"
                    status = "Unmitigated"
            elif 'expenditure' in risk_lower or 'expense' in risk_lower:
                if any('expense' in section_data['content'].lower() or 'submission' in section_data['content'].lower() 
                       for section_data in sections.values()):
                    policy_coverage = "Fully Covered"
                else:
                    policy_coverage = "Uncovered"
                    status = "Unmitigated"
            else:
                policy_coverage = "Partially Covered"
                status = "Partially Mitigated"

            for finding in findings:
                if finding.finding_type in ["CONFLICT", "INCONSISTENCY"]:
                    linked_findings.append(finding.finding_id)
                    if status == "Mitigated":
                        status = "Partially Mitigated"

            notes = f"Risk {risk_id} is {status.lower()} with {policy_coverage.lower()} policy coverage"

            risk_findings.append(RiskFinding(
                risk_id=risk_id,
                risk_text=risk,
                status=status,
                policy_coverage=policy_coverage,
                linked_findings=linked_findings,
                notes=notes
            ))

        return risk_findings

    async def _score_finding_confidence(self, finding_type: str, finding_description: str, cited_excerpts: list[str]) -> tuple[float, str]:
        """Use LLM to determine confidence score for a finding. Throws error if LLM fails."""
        prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a policy analysis expert. Given a finding, determine its confidence score (0-100%) and provide a one-line reason.

Consider:
- Explicitness of evidence in policy text
- Clarity of the issue described
- Potential for misinterpretation
- Completeness of cited excerpts

Respond in JSON format: {"confidence_score": <number>, "reason": "<one-line reason>"}"""),
            ("user", f"""Assess confidence for this {finding_type} finding:

Description: {finding_description}

Cited Excerpts:
{chr(10).join([f"- {excerpt[:200]}" for excerpt in cited_excerpts])}

Provide confidence score (0-100) and reason.""")
        ])
        
        response = await self.llm.ainvoke(prompt.format_messages())
        response_text = response.content
        
        import json
        parsed = json.loads(response_text)
        score = float(parsed.get("confidence_score"))
        reason = str(parsed.get("reason"))
        
        if not isinstance(score, (int, float)) or score < 0 or score > 100:
            raise ValueError(f"Invalid confidence score from LLM: {score}. Must be 0-100.")
        
        if not reason or not isinstance(reason, str):
            raise ValueError(f"Invalid reason from LLM: {reason}. Must be non-empty string.")
        
        logger.info(f"LLM confidence score for {finding_type}: {score}% - {reason}")
        return float(score), reason

    async def _llm_analyze_findings(self, policy_template: str, controls: list[str], risks: list[str]) -> dict:
        """Use LLM to perform sophisticated analysis based on system prompt."""
        try:
            prompt = ChatPromptTemplate.from_messages([
                ("system", self.SYSTEM_PROMPT),
                ("user", f"""Analyze this policy for conflicts, inconsistencies, and blind spots.

POLICY TEMPLATE:
{policy_template[:4000]}

CONTROLS:
{chr(10).join(controls)}

RELATED RISKS:
{chr(10).join(risks)}

Provide findings in JSON format with exact section citations and confidence scores.""")
            ])
            
            response = await self.llm.ainvoke(prompt.format_messages())
            logger.info("LLM analysis completed")
            return {"llm_analysis": response.content}
        except Exception as e:
            logger.warning(f"LLM analysis failed, falling back to rule-based detection: {e}")
            return {"llm_analysis": None}

    async def analyze_policy(self, policy_data: dict) -> dict:
        """Perform comprehensive policy review analysis without external references."""
        try:
            logger.info(f"Starting policy review analysis for: {policy_data.get('documentName')}")
            
            template = policy_data.get('template', '')
            if not template:
                logger.error("No policy template provided")
                return {
                    "success": False,
                    "error": "Policy template is required",
                    "document_name": policy_data.get('documentName', ''),
                    "document_id": "UNKNOWN",
                    "document_version": "1.0",
                    "analysis_timestamp": datetime.utcnow().isoformat(),
                    "findings": [],
                    "control_analysis": [],
                    "risk_analysis": [],
                    "summary": {},
                    "overall_compliance_status": "Unknown"
                }
            
            doc_id, doc_version = self._extract_document_id_and_version(template)
            sections = self._extract_sections(template)
            
            logger.info(f"Extracted document: {doc_id} v{doc_version} with {len(sections)} sections")
            
            llm_result = await self._llm_analyze_findings(
                template,
                policy_data.get('controls', []),
                policy_data.get('relatedRisks', [])
            )

            conflicts = await self._detect_conflicts(sections, [])
            inconsistencies = await self._detect_inconsistencies(sections, [])
            blind_spots = await self._detect_blind_spots(sections, policy_data.get('controls', []), policy_data.get('relatedRisks', []))
            
            all_findings = conflicts + inconsistencies + blind_spots
            
            logger.info(f"Detected {len(conflicts)} conflicts, {len(inconsistencies)} inconsistencies, {len(blind_spots)} blind spots")

            control_analysis = self._analyze_controls(policy_data.get('controls', []), all_findings)
            risk_analysis = self._analyze_risks(policy_data.get('relatedRisks', []), all_findings, sections)
            
            blocking_count = len([f for f in all_findings if f.severity == "Blocking"])
            non_blocking_count = len([f for f in all_findings if f.severity == "Non-Blocking"])
            advisory_count = len([f for f in all_findings if f.severity == "Advisory"])
            
            if blocking_count > 0:
                overall_status = "Non-Compliant"
            elif non_blocking_count > 0:
                overall_status = "Compliant with Exceptions"
            else:
                overall_status = "Compliant"

            summary = {
                "total_findings": len(all_findings),
                "conflicts": len(conflicts),
                "inconsistencies": len(inconsistencies),
                "blind_spots": len(blind_spots),
                "blocking_findings": blocking_count,
                "non_blocking_findings": non_blocking_count,
                "advisory_findings": advisory_count,
                "controls_enforceable": len([c for c in control_analysis if c.status == "Enforceable"]),
                "controls_partially_enforceable": len([c for c in control_analysis if c.status == "Partially Enforceable"]),
                "controls_unenforceable": len([c for c in control_analysis if c.status == "Unenforceable"]),
                "risks_mitigated": len([r for r in risk_analysis if r.status == "Mitigated"]),
                "risks_partially_mitigated": len([r for r in risk_analysis if r.status == "Partially Mitigated"]),
                "risks_unmitigated": len([r for r in risk_analysis if r.status == "Unmitigated"]),
                "sections_analyzed": len(sections),
            }

            return {
                "success": True,
                "document_name": policy_data.get('documentName', ''),
                "document_id": doc_id,
                "document_version": doc_version,
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "findings": [f.model_dump() for f in all_findings],
                "control_analysis": [c.model_dump() for c in control_analysis],
                "risk_analysis": [r.model_dump() for r in risk_analysis],
                "summary": summary,
                "overall_compliance_status": overall_status
            }

        except Exception as e:
            logger.error(f"Policy review analysis failed: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "document_name": policy_data.get('documentName', ''),
                "document_id": "UNKNOWN",
                "document_version": "1.0",
                "analysis_timestamp": datetime.utcnow().isoformat(),
                "findings": [],
                "control_analysis": [],
                "risk_analysis": [],
                "summary": {},
                "overall_compliance_status": "Unknown"
            }
