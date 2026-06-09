# Section-Level Policy Gap Analysis API

## Overview

This feature performs **atomic section-level gap analysis** for individual policies against a specific risk. After identifying the top 5 impacted policies, users can click "AI Analysis" on any policy to get a detailed breakdown of how each section addresses (or fails to address) the risk.

The system automatically **drafts new policy sections** for gaps identified as "Partially Covered" or "Missing".

## API Endpoint

### POST `/policies/gap-analysis`

Analyzes each section of a specific policy against a risk and provides coverage classification with recommendations.

#### Request Body

```json
{
  "risk_id": 1,
  "risk_title": "Inadequate AI Model Validation Process",
  "risk_description": "Machine learning models are being deployed to production without proper validation, bias testing, or explainability documentation.",
  "policy_name": "AI Governance and Model Risk Policy"
}
```

**Fields:**
- `risk_id` (integer, required): The ID of the risk from the database
- `risk_title` (string, required): The title/name of the risk
- `risk_description` (string, required): Detailed description of the risk
- `policy_name` (string, required): Name of the policy to analyze (partial match supported)

#### Response

```json
{
  "success": true,
  "risk_id": 1,
  "risk_title": "Inadequate AI Model Validation Process",
  "policy_name": "AI Governance and Model Risk Policy",
  "section_analyses": [
    {
      "section_number": "1",
      "section_title": "Purpose and Scope",
      "coverage_status": "No Impact",
      "gap_analysis": "This section defines the overall purpose and scope of the policy. It does not contain specific controls or requirements related to model validation processes, making it not directly relevant to the identified risk.",
      "recommended_section": null
    },
    {
      "section_number": "2.1",
      "section_title": "Model Development Lifecycle",
      "coverage_status": "Partially Covered",
      "gap_analysis": "The section outlines general model development stages but lacks specific requirements for validation procedures, bias testing protocols, and explainability documentation. While it mentions model testing, it does not mandate comprehensive validation before production deployment.",
      "recommended_section": "**Section 2.1.5: Model Validation and Testing Requirements**\n\nPrior to production deployment, all AI/ML models must undergo comprehensive validation including:\n\na) **Performance Validation**: Models must be tested against holdout datasets representing production conditions, with documented performance metrics meeting minimum thresholds defined by the Model Risk Committee.\n\nb) **Bias Testing**: All models affecting customer decisions must undergo bias testing across protected characteristics (age, gender, race, ethnicity, etc.) using statistical parity, equal opportunity, and disparate impact metrics. Any bias exceeding regulatory thresholds must be documented and mitigated.\n\nc) **Explainability Documentation**: Models must include:\n   - Feature importance analysis\n   - Decision boundary visualization for critical use cases\n   - Plain-language explanations of model logic suitable for regulatory review\n   - SHAP or LIME analysis for individual predictions in high-stakes scenarios\n\nd) **Validation Sign-off**: The Chief Data Officer and Model Risk Officer must formally approve all validation documentation before production deployment.\n\ne) **Ongoing Monitoring**: Post-deployment model performance must be monitored continuously with automated alerts for performance degradation, bias drift, or explainability issues."
    },
    {
      "section_number": "2.2",
      "section_title": "Model Governance Framework",
      "coverage_status": "Partially Covered",
      "gap_analysis": "The governance framework establishes oversight structures but does not specify mandatory validation gates or approval requirements for production deployment. The risk of deploying unvalidated models could occur if governance checkpoints are not enforced.",
      "recommended_section": "**Section 2.2.4: Mandatory Validation Gates**\n\nThe following validation gates are mandatory and must be completed before any model progresses to production:\n\n**Gate 1 - Development Completion**:\n- Model architecture documentation\n- Training data quality assessment\n- Initial performance benchmarks\n- Approval: Lead Data Scientist\n\n**Gate 2 - Validation Review**:\n- Comprehensive validation testing (per Section 2.1.5)\n- Bias testing results\n- Explainability documentation\n- Model risk assessment\n- Approval: Model Risk Officer\n\n**Gate 3 - Production Readiness**:\n- Infrastructure security review\n- Operational runbook\n- Monitoring and alerting configuration\n- Rollback procedures\n- Approval: Chief Data Officer and Chief Information Security Officer\n\nNo model may be deployed to production without documented approval at all three gates. Violations will be escalated to the Executive Risk Committee."
    },
    {
      "section_number": "3.1",
      "section_title": "Model Risk Classification",
      "coverage_status": "Fully Covered",
      "gap_analysis": "This section provides a comprehensive risk classification framework that would appropriately categorize models deployed without validation as high-risk, triggering enhanced oversight requirements. The classification criteria adequately address the risk scenario.",
      "recommended_section": null
    },
    {
      "section_number": "4.1",
      "section_title": "Third-Party Model Risk",
      "coverage_status": "No Impact",
      "gap_analysis": "This section addresses risks from externally developed models and vendor management. The identified risk pertains to internal model development processes, making this section not directly relevant.",
      "recommended_section": null
    },
    {
      "section_number": "5.1",
      "section_title": "Model Documentation Requirements",
      "coverage_status": "Missing",
      "gap_analysis": "While the section lists general documentation requirements, it completely omits mandatory explainability documentation and bias testing reports. This is a critical gap given regulatory expectations under AI governance frameworks (EU AI Act, NIST AI RMF).",
      "recommended_section": "**Section 5.1.6: Explainability and Fairness Documentation**\n\nAll AI/ML models must maintain the following documentation:\n\n**a) Model Explainability Package**:\n- Global interpretability analysis showing overall model behavior\n- Feature importance rankings with statistical significance\n- Decision tree approximations for complex models\n- Counterfactual explanations for key decision scenarios\n- Plain-language model cards suitable for non-technical stakeholders\n\n**b) Bias Testing and Fairness Report**:\n- Protected attribute analysis across all relevant demographic groups\n- Statistical parity metrics with confidence intervals\n- Equal opportunity and equalized odds measurements\n- Disparate impact ratios compared to regulatory thresholds (e.g., 80% rule)\n- Mitigation strategies for identified biases\n- Ongoing monitoring plan for bias drift\n\n**c) Regulatory Compliance Mapping**:\n- Alignment with EU AI Act requirements (if applicable)\n- NIST AI Risk Management Framework compliance\n- Industry-specific regulations (e.g., fair lending laws for credit models)\n\n**d) Documentation Maintenance**:\n- All documentation must be updated within 30 days of model changes\n- Annual comprehensive review by Model Risk Committee\n- Version control with audit trail of all changes\n\nFailure to maintain current explainability and fairness documentation will result in immediate model suspension pending remediation."
    }
  ],
  "summary": {
    "total_sections": 6,
    "fully_covered": 1,
    "partially_covered": 2,
    "missing": 1,
    "no_impact": 2,
    "sections_needing_action": 3
  }
}
```

**Response Fields:**
- `success` (boolean): Indicates if the analysis was successful
- `risk_id` (integer): The ID of the analyzed risk
- `risk_title` (string): The title of the analyzed risk
- `policy_name` (string): The name of the analyzed policy
- `section_analyses` (array): Detailed analysis for each policy section
  - `section_number` (string): Section identifier (e.g., "1", "2.1", "3.2.1")
  - `section_title` (string): Title of the section
  - `coverage_status` (string): One of:
    - **"Fully Covered"**: Section comprehensively addresses the risk
    - **"Partially Covered"**: Section has some controls but notable gaps exist
    - **"Missing"**: Section has no meaningful coverage of the risk
    - **"No Impact"**: Section is not relevant to this risk
  - `gap_analysis` (string): Detailed explanation of the coverage status and specific gaps
  - `recommended_section` (string | null): Drafted policy section text to address gaps (only for Partially Covered or Missing)
- `summary` (object): Statistics about the analysis
  - `total_sections`: Total number of sections analyzed
  - `fully_covered`: Count of fully covered sections
  - `partially_covered`: Count of partially covered sections
  - `missing`: Count of missing coverage sections
  - `no_impact`: Count of non-relevant sections
  - `sections_needing_action`: Count of sections requiring remediation (Partially Covered + Missing)

## Complete User Workflow

### Step 1: Create Risk
```bash
POST /risks
{
  "title": "Inadequate AI Model Validation Process",
  "description": "ML models deployed without validation, bias testing, or explainability",
  "category": ["AI/ML", "Model Risk"]
}
```

### Step 2: Analyze Policy Impact
```bash
POST /risks/analyze-policy-impact
{
  "risk_id": 1,
  "risk_title": "Inadequate AI Model Validation Process",
  "risk_description": "ML models deployed without validation, bias testing, or explainability"
}
```

**Response**: Top 5 impacted policies with scores

### Step 3: Click "AI Analysis" on Specific Policy
```bash
POST /policies/gap-analysis
{
  "risk_id": 1,
  "risk_title": "Inadequate AI Model Validation Process",
  "risk_description": "ML models deployed without validation, bias testing, or explainability",
  "policy_name": "AI Governance and Model Risk Policy"
}
```

**Response**: Section-by-section gap analysis with drafted recommendations

## Technical Implementation

### Architecture

```
┌─────────────────────┐
│   FastAPI           │
│   /policies/        │
│   gap-analysis      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ PolicyGapAnalyzer   │
│ (Service Layer)     │
└──────────┬──────────┘
           │
           ├──► 1. Find Policy PDF
           │
           ├──► 2. Extract Full Content
           │
           ├──► 3. Parse Sections (LLM-based)
           │
           ├──► 4. Analyze Each Section
           │    └──► Classify Coverage
           │    └──► Identify Gaps
           │    └──► Draft Recommendations
           │
           └──► 5. Return Results + Summary
```

### Key Components

1. **Policy Section Parser**: 
   - Uses GPT-4o to intelligently identify sections
   - Fallback regex parsing for robustness
   - Handles hierarchical sections (1, 1.1, 1.2, etc.)

2. **Coverage Classifier**:
   - GRC expert system prompt
   - 4-tier classification (Fully Covered, Partially Covered, Missing, No Impact)
   - Considers regulatory violations, operational risks, control gaps

3. **Recommendation Engine**:
   - Auto-drafts policy sections for gaps
   - Professional policy language
   - Includes specific, actionable requirements
   - References regulatory frameworks

### Files Modified/Created

- **`schemas/requests.py`**: Added `PolicyGapAnalysisRequest`
- **`schemas/responses.py`**: Added `SectionGapAnalysis`, `PolicyGapAnalysisResponse`
- **`services/policy_gap_analyzer.py`**: Core gap analysis logic (NEW)
- **`main.py`**: Added `/policies/gap-analysis` endpoint

## Example Use Cases

### Use Case 1: Cybersecurity Risk

**Risk**: Third-Party API Security Breach

**Policy**: ICT Risk Management and Cyber Security Policy

**Expected Output**:
- Section on "Access Controls" → **Partially Covered** (lacks MFA requirements)
- Section on "Third-Party Risk" → **Missing** (no API security protocols)
- Section on "Incident Response" → **Fully Covered**
- Drafted sections for access controls and API security

### Use Case 2: Compliance Risk

**Risk**: GDPR Data Subject Rights Violations

**Policy**: Group AML / CFT and Sanctions Policy

**Expected Output**:
- Section on "Customer Data" → **Partially Covered** (lacks GDPR-specific procedures)
- Section on "Data Retention" → **Missing** (no right to erasure process)
- Drafted sections for GDPR compliance procedures

### Use Case 3: Operational Risk

**Risk**: Business Continuity Failure in Payment Systems

**Policy**: Digital Operational Resilience DORA Policy

**Expected Output**:
- Section on "Resilience Testing" → **Fully Covered**
- Section on "Recovery Procedures" → **Partially Covered** (lacks payment-specific RTO/RPO)
- Drafted section for payment system recovery requirements

## Performance Considerations

- **Analysis Time**: 20-40 seconds per policy (depends on number of sections)
- **Token Usage**: ~2,000-4,000 tokens per section analysis
- **Typical Policy**: 4-8 sections = 8,000-32,000 tokens total
- **Cost Estimate**: $0.10-$0.40 per policy analysis (GPT-4o pricing)

## Best Practices

### For Frontend Integration

1. **Show Loading State**: Analysis takes 20-40 seconds
2. **Display Progress**: "Analyzing section 3 of 6..."
3. **Highlight Action Items**: Emphasize Partially Covered and Missing sections
4. **Collapsible Sections**: Allow users to expand/collapse recommendations
5. **Export Functionality**: Enable PDF/Word export of drafted sections

### For Policy Updates

1. **Review Recommendations**: AI-drafted sections should be reviewed by compliance officers
2. **Customize Language**: Adapt to organization's policy style
3. **Regulatory Alignment**: Verify regulatory references are applicable
4. **Version Control**: Track policy changes resulting from gap analysis
5. **Approval Workflow**: Route drafted sections through governance process

## Error Handling

### Common Errors

1. **404 - Risk Not Found**
   ```json
   {
     "success": false,
     "message": "Risk not found"
   }
   ```

2. **400 - Policy Not Found**
   ```json
   {
     "success": false,
     "message": "Policy 'XYZ Policy' not found in Files/policies"
   }
   ```

3. **400 - No Sections Found**
   ```json
   {
     "success": false,
     "message": "No sections found in policy 'ABC Policy'"
   }
   ```

4. **500 - Analysis Failed**
   ```json
   {
     "success": false,
     "message": "Failed to analyze policy gaps: [error details]"
   }
   ```

## Future Enhancements

1. **Database Storage**: Store gap analysis results for historical tracking
2. **Comparison View**: Compare analyses across multiple risks
3. **Policy Versioning**: Track how policies evolve based on gap analyses
4. **Bulk Analysis**: Analyze all top 5 policies simultaneously
5. **Custom Sections**: Allow users to add custom sections for analysis
6. **Approval Workflow**: Integrate drafted sections into policy approval process
7. **Regulatory Mapping**: Auto-map recommendations to specific regulations
8. **Impact Scoring**: Score each gap by severity and urgency
