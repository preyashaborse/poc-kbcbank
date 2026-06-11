POLICY_DATA_SEED = [
    {
        "documentName": "KBC Bank NV Belgium Local Travel Policy",
        "documentType": "Travel & Expense Policy",
        "approvalType": "Mandatory",
        "category": "Employee Expenses & Travel",
        "description": "Belgium-specific travel policy supplementing the KBC Group Global Travel Policy (POL-T001). Covers expense submission deadlines, air and rail travel rules, hotel rate limits, meal allowances, KATE AI assistant integration, and Belgian tax treatment for KBC Bank NV employees across Brussels HQ, KBC Tower, and all Belgian branches.",
        "effectiveFrom": "01/03/2025",
        "references": [
            {
                "url": "https://kbc.internal/policies/POL-T001-v1.2.pdf"
            }
        ],
        "template": """POL-T002 — KBC Bank NV Belgium Local Travel Policy — v2.1

1.0 Purpose
The purpose of this policy is to supplement the KBC Group Global Travel Policy (POL-T001) with Belgium-specific expense limits, booking procedures, local tax treatment, and guidance on using the KATE AI assistant for travel-related tasks. It applies exclusively to KBC Bank NV employees based in Belgium.

2.0 Scope
This policy applies to all employees of KBC Bank NV in Belgium, including staff at the Brussels headquarters, KBC Tower, and all Belgian branch and regional office locations. Employees of KBC Insurance NV, KBC Asset Management NV, or other Belgian KBC Group entities should refer to their entity-specific HR documentation.

3.0 Policy Statement

3.1 Expense Submission
Employees must submit expense claims within 14 calendar days of completing a business trip (stricter than the Group standard of 30 days). Claims submitted after 21 days require line manager confirmation. Claims after 90 days follow the Group exception process.

3.2 Air Travel
Economy class is required for all flights of 4 hours or less. Business class is permitted for Senior Manager level and above on flights exceeding 4 hours, subject to pre-approval. Premium economy is permitted for all Belgian employees on flights between 3 and 4 hours. For Brussels–London travel, Eurostar is the required mode of transport; flights on this route are not reimbursable without documented justification.

3.3 Rail Travel
NMBS/SNCB second class is standard for all domestic Belgian journeys. First class is permitted for journeys over 2 hours or for Manager level and above during peak hours. Thalys, Eurostar, and ICE bookings must be made through the KBC Travel Portal.

3.4 Accommodation Rate Limits
- Brussels: EUR 180/night (exception EUR 220 with Finance Director approval)
- Antwerp / Ghent / Bruges: EUR 150/night (exception EUR 190 with line manager approval)
- Other Belgian cities: EUR 120/night (exception EUR 150 with line manager approval)
- Luxembourg City: EUR 190/night (exception EUR 230 with Finance Director approval)
- Amsterdam / Paris / Frankfurt: EUR 200/night (exception EUR 250 with Finance Director approval)
- London: GBP 220/night (exception GBP 270 with Finance Director approval)

3.5 Meals and Subsistence (Belgian Flat-Rate Allowances)
- Domestic travel (Belgium): EUR 20.00/day — tax-exempt, no receipt required
- International travel (EU): EUR 45.00/day
- International travel (non-EU): EUR 55.00/day (country-specific rates on intranet)
- Day trip (no overnight, >10 hours from home base): EUR 10.00/day

3.6 Ground Transportation
Brussels business journeys should use the KBC corporate De Lijn/MIVB public transport account. Taxis and Uber (standard service only) are permitted where public transport is impractical. Private car mileage reimbursement is EUR 0.42/km (2025 Belgian fiscal rate).

3.7 KATE AI Travel Assistant
KATE is available via KBC Mobile and the KBC Business Dashboard. It assists with flight and hotel searches, policy threshold checks, and pre-approval initiation. Bookings within policy are processed automatically; bookings above threshold trigger an approval workflow. Employees should flag any booking they believe conflicts with this policy to the Finance team.

3.8 Expense Reporting
All expense claims must be submitted through SAP Concur. Receipts must be uploaded as clear digital images or PDFs. Offline submission by email to the Finance team is available during system outages but delays processing by approximately 5 business days.

4.0 Enforcement
All violations of this policy will be subject to disciplinary action in accordance with the KBC Group Global Travel Policy (Section 12) and the KBC Bank NV disciplinary framework. For Belgian-specific provisions — in particular the Belgian tax treatment sections — non-compliance may have direct financial consequences for both the employee and KBC Bank NV. Exceptions resulting in reimbursement above Belgian flat-rate allowances must be reviewed by the HR Compensation & Benefits team for tax compliance. Repeated violations may result in withdrawal of travel booking privileges or escalation to formal disciplinary proceedings.

5.0 Definitions
Dagvergoeding / Indemnité journalière: Belgian tax-exempt flat-rate daily subsistence allowance published by the Belgian Federal Public Service Finance.
Bedrijfsvoorheffing / Précompte professionnel: Belgian withholding tax applied to remuneration and reimbursements exceeding published flat-rate allowances.
KATE: KBC's AI digital assistant, integrated into the travel booking and expense workflow.
KBC Travel Portal: Primary platform for booking flights, rail, and hotels within KBC policy parameters.
SAP Concur: KBC Bank NV's mandatory expense claim submission system.
Voordeel van alle aard / Avantage de toute nature: The taxable benefit-in-kind applied to private use of a company car, reported separately from expense claims.
Senior Manager: An employee at or above the grade designated as Senior Manager in KBC Bank NV's HR classification, eligible for business class travel on flights exceeding 4 hours.""",
        "controls": [
            "CTR-001-Pre-Travel Approval Gate (EUR 800 Threshold): Automated block in KATE and KBC Travel Portal prevents booking confirmation for trips where estimated total cost exceeds EUR 800 without line manager approval recorded in the workflow."
        ],
        "risks": [
            "RTR-001-Unapproved Business Travel Expenditure-Belgian employees incur business travel costs without obtaining required pre-approval, resulting in financial exposure and audit findings. Risk is heightened by KATE's automated booking capability which may bypass line manager approval workflows.",
        ],
    }
]
