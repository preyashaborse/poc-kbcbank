# Policy Impact Analysis API

## Overview

This feature analyzes which policies are most impacted by a created risk. It uses AI-powered analysis to evaluate all 16 policies stored in the `Files/policies` folder and returns the top 5 most impacted policies with detailed rationale and impact scores.

## API Endpoint

### POST `/risks/analyze-policy-impact`

Analyzes the impact of a risk on all available policies and returns the top 5 most impacted policies.

#### Request Body

```json
{
  "risk_id": 1,
  "risk_title": "Data Breach in Customer Database",
  "risk_description": "Potential unauthorized access to customer personal data due to weak authentication controls"
}
```

**Fields:**
- `risk_id` (integer, required): The ID of the risk from the database
- `risk_title` (string, required): The title/name of the risk
- `risk_description` (string, required): Detailed description of the risk

#### Response

```json
{
  "success": true,
  "risk_id": 1,
  "risk_title": "Data Breach in Customer Database",
  "impacted_policies": [
    {
      "policy_name": "ICT Risk Management and Cyber Security Policy",
      "rationale": "This risk directly impacts the ICT Risk Management policy as it involves cybersecurity controls, authentication mechanisms, and data protection measures. The weak authentication controls mentioned in the risk description represent a critical gap in the security framework outlined in this policy.",
      "score": 92.5
    },
    {
      "policy_name": "Group AML / CFT and Sanctions Policy",
      "rationale": "Customer data breaches can expose sensitive KYC information and transaction data, potentially compromising AML/CFT compliance and customer due diligence processes.",
      "score": 78.0
    },
    {
      "policy_name": "Private Banking KYC and Enhanced Due Diligence",
      "rationale": "Unauthorized access to customer databases directly threatens the confidentiality of KYC data and enhanced due diligence records for high-risk customers.",
      "score": 75.5
    },
    {
      "policy_name": "Digital Operational Resilience DORA Policy",
      "rationale": "The risk affects operational resilience by threatening the availability and integrity of critical customer data systems.",
      "score": 68.0
    },
    {
      "policy_name": "Payment Services and Fraud Prevention Policy",
      "rationale": "Customer data breaches can lead to payment fraud and unauthorized transactions if customer credentials are compromised.",
      "score": 65.0
    }
  ]
}
```

**Response Fields:**
- `success` (boolean): Indicates if the analysis was successful
- `risk_id` (integer): The ID of the analyzed risk
- `risk_title` (string): The title of the analyzed risk
- `impacted_policies` (array): List of top 5 impacted policies, each containing:
  - `policy_name` (string): Name of the policy
  - `rationale` (string): Detailed explanation of how the risk impacts this policy
  - `score` (float): Impact score from 0-100, where:
    - 0-20: Minimal or no impact
    - 21-40: Low impact
    - 41-60: Moderate impact
    - 61-80: High impact
    - 81-100: Critical impact

## Workflow

### Complete Risk Creation and Analysis Flow

1. **Create a Risk** using the existing `/risks` endpoint:
   ```bash
   POST /risks
   {
     "title": "Data Breach in Customer Database",
     "description": "Potential unauthorized access to customer personal data",
     "category": ["Cybersecurity", "Data Protection"]
   }
   ```

2. **Risk is stored in database** and a `RiskResponse` is returned with the risk ID

3. **Analyze Policy Impact** using the new endpoint:
   ```bash
   POST /risks/analyze-policy-impact
   {
     "risk_id": 1,
     "risk_title": "Data Breach in Customer Database",
     "risk_description": "Potential unauthorized access to customer personal data"
   }
   ```

4. **Receive top 5 impacted policies** with detailed rationale and scores

## Technical Implementation

### Architecture

```
┌─────────────────┐
│   FastAPI       │
│   main.py       │
│   (Routes)      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ PolicyAnalyzer  │
│ (Service Layer) │
└────────┬────────┘
         │
         ├──► Load PDFs from Files/policies/
         │
         ├──► Extract policy content
         │
         ├──► Analyze with GPT-4
         │
         └──► Return top 5 ranked results
```

### Key Components

1. **`schemas/requests.py`**: Contains `AnalyzePolicyImpactRequest` schema
2. **`schemas/responses.py`**: Contains `PolicyImpact` and `AnalyzePolicyImpactResponse` schemas
3. **`services/policy_analyzer.py`**: Core analysis logic using LangChain and OpenAI
4. **`main.py`**: FastAPI endpoint implementation

### Policy Analysis Process

1. **Policy Loading**: Reads all PDF files from `Files/policies/` folder
2. **Content Extraction**: Extracts text content from each policy PDF (limited to 8000 chars)
3. **AI Analysis**: Uses GPT-4 to analyze each policy against the risk context
4. **Scoring**: Assigns impact scores (0-100) based on:
   - Direct regulatory violations
   - Operational risk exposure
   - Financial implications
   - Reputational damage
   - Control gaps
5. **Ranking**: Sorts policies by impact score and returns top 5

## Environment Setup

### Required Environment Variables

Add to your `.env` file:

```env
OPENAI_API_KEY=your_openai_api_key_here
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

New dependencies added:
- `langchain`: Framework for LLM applications
- `langchain-openai`: OpenAI integration for LangChain
- `langchain-community`: Community integrations including PDF loaders
- `pypdf`: PDF parsing library
- `openai`: OpenAI API client

## Example Usage

### Using cURL

```bash
curl -X POST "http://localhost:5000/risks/analyze-policy-impact" \
  -H "Content-Type: application/json" \
  -d '{
    "risk_id": 1,
    "risk_title": "Inadequate AI Model Validation",
    "risk_description": "Machine learning models deployed without proper validation and bias testing"
  }'
```

### Using Python Requests

```python
import requests

response = requests.post(
    "http://localhost:5000/risks/analyze-policy-impact",
    json={
        "risk_id": 1,
        "risk_title": "Inadequate AI Model Validation",
        "risk_description": "Machine learning models deployed without proper validation and bias testing"
    }
)

result = response.json()
print(f"Success: {result['success']}")
print(f"\nTop 5 Impacted Policies:")
for policy in result['impacted_policies']:
    print(f"\n{policy['policy_name']} (Score: {policy['score']}%)")
    print(f"Rationale: {policy['rationale']}")
```

## Error Handling

### Common Errors

1. **404 - Risk Not Found**
   ```json
   {
     "success": false,
     "message": "Risk not found"
   }
   ```

2. **400 - No Policies Found**
   ```json
   {
     "success": false,
     "message": "No policy files found in Files/policies"
   }
   ```

3. **500 - Analysis Failed**
   ```json
   {
     "success": false,
     "message": "Failed to analyze policy impact: [error details]"
   }
   ```

## Performance Considerations

- **Analysis Time**: Analyzing 16 policies takes approximately 30-60 seconds depending on API response times
- **Token Usage**: Each policy analysis consumes OpenAI API tokens (approximately 1000-2000 tokens per policy)
- **Caching**: Consider implementing caching for repeated analyses of the same risk
- **Async Processing**: For production, consider making this an async background job

## Future Enhancements

1. **Caching**: Store analysis results to avoid re-analyzing the same risks
2. **Background Jobs**: Move analysis to background queue for better UX
3. **Customizable Top N**: Allow clients to specify how many policies to return
4. **Policy Embeddings**: Pre-compute policy embeddings for faster similarity search
5. **Historical Tracking**: Store analysis results in database for audit trail
