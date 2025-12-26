## PDF Report Generation

The PDF Reporter generates professional, executive-ready security reports with:

- **Cover Page**: Company branding, environment details, scan metadata
- **Executive Summary**: High-level risk overview, severity breakdown, top issues
- **Risk Dashboard**: Overall risk score, findings by category
- **Detailed Findings**: Comprehensive listing of all security issues
- **Compliance Mapping**: SOC 2, PCI-DSS, HIPAA, ISO 27001 controls
- **Recommendations**: Actionable next steps

### Installation

```bash
pip install reportlab
```

### Usage

#### CLI

```bash
# Generate PDF report
cloudguard-anomaly scan --env ./environment --format pdf

# Generate all formats including PDF
cloudguard-anomaly scan --env ./environment --format all
```

#### Python API

```python
from cloudguard_anomaly.reports import PDFReporter

# Initialize reporter
reporter = PDFReporter(page_size='letter')  # or 'a4'

# Generate report
reporter.generate_report(
    scan_results=scan_data,
    output_path='report.pdf',
    include_executive_summary=True,
    include_detailed_findings=True,
    include_compliance_mapping=True,
    company_name='Acme Corporation',
    logo_path='logo.png'  # Optional company logo
)
```

### Features

#### Executive Summary
- Risk score calculation (0-100)
- Severity breakdown table
- Top 3 priority issues
- Risk level classification (Critical/High/Medium/Low)

#### Risk Dashboard
- Overall risk scoring
- Findings categorized by type (misconfiguration, compliance, etc.)
- Visual severity distribution

#### Detailed Findings
- Grouped by severity (Critical, High, Medium, Low)
- Resource identification
- Policy violations
- Descriptions and remediation steps
- Pagination with page numbers

#### Compliance Mapping
- SOC 2 controls
- PCI-DSS requirements
- HIPAA regulations
- ISO 27001 standards

### Customization

```python
# Custom page size
reporter = PDFReporter(page_size='a4')

# Minimal report (cover page + findings only)
reporter.generate_report(
    scan_results=results,
    output_path='minimal.pdf',
    include_executive_summary=False,
    include_compliance_mapping=False
)

# With company branding
reporter.generate_report(
    scan_results=results,
    output_path='branded.pdf',
    company_name='YourCompany Inc.',
    logo_path='/path/to/logo.png'
)
```

### Output Example

The generated PDF includes:
1. Professional cover page with scan metadata
2. Executive summary with risk analysis
3. Color-coded severity tables
4. Detailed finding descriptions
5. Remediation recommendations
6. Compliance framework mapping
7. Page numbers and timestamps

### Report Structure

```
report.pdf
├── Cover Page
│   ├── Company logo (if provided)
│   ├── Report title
│   ├── Environment name
│   └── Scan metadata
│
├── Executive Summary
│   ├── Risk overview paragraph
│   ├── Severity distribution table
│   └── Top 3 priority issues
│
├── Risk Dashboard
│   ├── Overall risk score
│   ├── Risk level classification
│   └── Findings by category
│
├── Detailed Findings
│   ├── Critical findings
│   ├── High severity findings
│   ├── Medium severity findings
│   └── Low severity findings
│
├── Compliance Mapping
│   ├── SOC 2 controls
│   ├── PCI-DSS requirements
│   ├── HIPAA regulations
│   └── ISO 27001 standards
│
└── Recommendations
    └── Actionable next steps
```

### Styling

The PDF uses professional styling:
- **Colors**: Blue headers, severity-coded findings
- **Fonts**: Helvetica family for readability
- **Layout**: Clean, well-spaced design
- **Tables**: Alternating row colors for clarity
- **Pagination**: Automatic page breaks with headers/footers

### Performance

- Small reports (<100 findings): ~1-2 seconds
- Medium reports (100-500 findings): ~3-5 seconds
- Large reports (500+ findings): ~5-10 seconds

### Troubleshooting

**ImportError: ReportLab required**
```bash
pip install reportlab
```

**Logo not displaying**
- Verify logo path is correct
- Use PNG or JPEG format
- Recommended size: 2" wide x 1" tall

**PDF too large**
- Limit findings in detailed section (default: 10 per severity)
- Reduce image sizes
- Disable optional sections

### CI/CD Integration

```yaml
# GitHub Actions
- name: Generate PDF Report
  run: |
    pip install reportlab
    cloudguard-anomaly scan --env ./infra --format pdf

- name: Upload PDF Report
  uses: actions/upload-artifact@v3
  with:
    name: security-report
    path: ./reports/*.pdf
```

### Additional Report Formats

- **JSON**: Machine-readable structured data
- **Markdown**: Human-readable text format
- **HTML**: Interactive web-based report

Generate all formats:
```bash
cloudguard-anomaly scan --env ./environment --format all
```

### License

MIT License - See LICENSE file for details

