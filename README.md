# CloudGuard-Anomaly: Agentic Cloud Security Posture & Anomaly Analyzer

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

CloudGuard-Anomaly is an agentic AI-powered framework for analyzing cloud security posture, detecting misconfigurations, and explaining configuration drift across multi-cloud environments.

## Features

### Core Security Capabilities
- **Multi-Cloud Support**: Analyze AWS, Azure, and GCP environments with provider-agnostic abstractions
- **Policy-as-Code Engine**: Extensible rule-based security checks based on industry standards (CIS, NIST, PCI-DSS)
- **Drift Detection**: Compare baseline configurations against current state to identify unauthorized changes
- **Compliance Frameworks**: Evaluate against SOC2, PCI-DSS, HIPAA, ISO 27001, and more
- **Threat Intelligence**: Enrich findings with threat indicators and contextual risk information
- **Comprehensive Reporting**: Generate JSON, Markdown, and HTML reports for different audiences

### Live Cloud Integration
- **Real-Time Scanning**: Discover and analyze live cloud resources using native SDKs
- **Multi-Provider Discovery**: AWS (boto3), Azure (Azure SDK), GCP (Google Cloud SDK)
- **Historical Tracking**: Database backend for trend analysis and compliance reporting
- **Web Dashboard**: Real-time monitoring with interactive visualizations

### AI & Machine Learning
- **LLM Integration**: Claude, OpenAI, and local LLM support for intelligent analysis
- **Agentic Explanations**: AI-powered agents provide human-readable explanations and remediation guidance
- **ML Anomaly Detection**: Isolation Forest-based behavioral anomaly detection
- **Automated Insights**: Natural language summaries and risk assessments

### Automation & Integration
- **Auto-Remediation**: Safe, dry-run enabled automatic fixing of common issues
- **CI/CD Integration**: Templates for GitLab CI, GitHub Actions, and Jenkins
- **Webhook Notifications**: Slack and custom webhook support
- **API & CLI**: Comprehensive command-line interface and Python API

### Enterprise Features
- **RBAC & Multi-Tenancy**: Role-based access control and organization management
- **Cost Analysis**: Estimate cloud costs and identify cost optimization opportunities
- **Audit Logging**: Complete audit trail for compliance and forensics
- **Synthetic Environments**: Test and demonstrate with built-in synthetic cloud scenarios

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     CloudGuard-Anomaly                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐        ┌─────────────────┐               │
│  │   Providers  │        │  Policy Engine  │               │
│  │  AWS/Azure/  │        │  - Baseline     │               │
│  │     GCP      │        │  - Provider     │               │
│  └──────────────┘        │    Specific     │               │
│         │                └─────────────────┘               │
│         │                        │                          │
│         ▼                        ▼                          │
│  ┌──────────────────────────────────────┐                  │
│  │       Analysis Engine                 │                  │
│  │  - Policy Evaluation                  │                  │
│  │  - Drift Detection                    │                  │
│  │  - Anomaly Identification             │                  │
│  └──────────────────────────────────────┘                  │
│         │                                                    │
│         ▼                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Misconfig    │  │   Identity   │  │   Network    │     │
│  │  Detector    │  │   Detector   │  │   Detector   │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│         │                  │                  │             │
│         └──────────────────┴──────────────────┘             │
│                            │                                 │
│                            ▼                                 │
│                  ┌─────────────────┐                        │
│                  │  Agentic Layer  │                        │
│                  │  - Explainers   │                        │
│                  │  - Planners     │                        │
│                  │  - Summarizers  │                        │
│                  └─────────────────┘                        │
│                            │                                 │
│                            ▼                                 │
│                  ┌─────────────────┐                        │
│                  │    Reporters    │                        │
│                  │ JSON/MD/HTML    │                        │
│                  └─────────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Python 3.11 or higher
- pip package manager

### Install from Source

```bash
git clone https://github.com/nik-kale/CloudGuard-Anomaly.git
cd CloudGuard-Anomaly
pip install -e .
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

Or install with development dependencies:

```bash
pip install -e ".[dev]"
```

A plain `pip install .` gives you file-based scanning. Add extras for the rest:
`.[dashboard]`, `.[aws]`, `.[pdf]`, `.[iac]` and `.[ml]`. `requirements.txt` installs everything.

## Quick Start

### 1. Scan Synthetic Environment (No Cloud Account Required)

```bash
# Generate a test environment
cloudguard-anomaly generate --name my-test-env --provider aws --with-issues

# Scan it
cloudguard-anomaly scan --env examples/environments/my-test-env
```

### 2. Scan Live Cloud Environment (Requires Cloud Credentials)

```bash
# AWS - uses AWS CLI credentials
cloudguard-anomaly live-scan --provider aws --profile production

# Azure - requires subscription ID
cloudguard-anomaly live-scan --provider azure --subscription-id <id>

# GCP - requires project ID
cloudguard-anomaly live-scan --provider gcp --project-id my-project
```

### 3. Evaluate Compliance

```bash
cloudguard-anomaly compliance --env ./infrastructure --framework soc2
```

### 4. Launch Web Dashboard

```bash
export DASHBOARD_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
cloudguard-anomaly dashboard --database-url sqlite:///cloudguard.db
```

Open your browser to `http://localhost:5000` for real-time monitoring.

### 5. View Reports

Reports are saved to `./reports/` by default:
- `<env-name>_report.json` - Structured findings in JSON format
- `<env-name>_report.md` - Human-readable Markdown report
- `<env-name>_report.html` - Interactive HTML dashboard

## Usage Examples

### Basic Scan

Scan an environment with built-in policies:

```bash
cloudguard-anomaly scan --env examples/environments/env_aws_small
```

### Custom Policies

Use custom policy files:

```bash
cloudguard-anomaly scan \
  --env examples/environments/env_aws_small \
  --policies /path/to/custom/policies
```

### Drift Detection

Scan an environment with drift detection enabled (default):

```bash
cloudguard-anomaly scan --env examples/drift_scenarios/public_bucket_after_change
```

### Output Formats

Generate specific report formats:

```bash
# JSON only
cloudguard-anomaly scan --env <path> --format json

# Markdown only
cloudguard-anomaly scan --env <path> --format markdown

# All formats (default)
cloudguard-anomaly scan --env <path> --format all
```

### Validate Configurations

Validate environment and policy files:

```bash
cloudguard-anomaly validate --env examples/environments/env_aws_small
cloudguard-anomaly validate --policies cloudguard_anomaly/policies/aws_policies.yaml
```

### Advanced Usage

#### Live Scanning with Database Persistence

```bash
cloudguard-anomaly live-scan \
  --provider aws \
  --profile production \
  --database-url postgresql://user:pass@localhost/cloudguard \
  --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

#### Compliance Evaluation

```bash
# SOC2 compliance
cloudguard-anomaly compliance --env ./infrastructure --framework soc2

# PCI-DSS compliance
cloudguard-anomaly compliance --env ./infrastructure --framework pci_dss --format json

# HIPAA compliance
cloudguard-anomaly compliance --env ./infrastructure --framework hipaa
```

#### Auto-Remediation (Dry Run)

```bash
# Dry run (safe, no changes made)
cloudguard-anomaly remediate --scan-id abc123 --dry-run --database-url sqlite:///cloudguard.db

# Remediate critical findings only
cloudguard-anomaly remediate --scan-id abc123 --severity critical --no-dry-run --database-url sqlite:///cloudguard.db
```

#### Machine Learning Model Training

```bash
# Train ML anomaly detection model
cloudguard-anomaly train-ml \
  --database-url sqlite:///cloudguard.db \
  --days 30 \
  --save-model anomaly_model.pkl
```

#### CI/CD Integration

```bash
# Fail build on critical findings
cloudguard-anomaly scan --env ./infrastructure --format json
# Exit code: 0 = pass, 1 = warnings, 2 = critical failures
```

## Project Structure

```
cloudguard-anomaly/
├── cloudguard_anomaly/          # Main package
│   ├── core/                     # Core engine and models
│   │   ├── models.py             # Data models
│   │   ├── engine.py             # Analysis orchestration
│   │   ├── loader.py             # Config loading
│   │   └── evaluator.py          # Policy evaluation
│   ├── providers/                # Cloud provider abstractions
│   │   ├── base.py               # Base provider interface
│   │   ├── aws.py                # AWS provider
│   │   ├── azure.py              # Azure provider
│   │   └── gcp.py                # GCP provider
│   ├── integrations/             # Live cloud integrations
│   │   ├── aws_live.py           # AWS SDK integration
│   │   ├── azure_live.py         # Azure SDK integration
│   │   └── gcp_live.py           # GCP SDK integration
│   ├── policies/                 # Security policies
│   │   ├── policy_engine.py      # Policy management
│   │   ├── baseline_policies.yaml
│   │   ├── aws_policies.yaml
│   │   ├── azure_policies.yaml
│   │   └── gcp_policies.yaml
│   ├── detectors/                # Detection modules
│   │   ├── misconfig_detector.py
│   │   ├── drift_detector.py
│   │   ├── identity_detector.py
│   │   └── network_detector.py
│   ├── agents/                   # Agentic components
│   │   ├── base_agent.py
│   │   ├── misconfig_explainer_agent.py
│   │   ├── drift_explainer_agent.py
│   │   ├── remediation_planner_agent.py
│   │   ├── risk_summarizer_agent.py
│   │   └── llm/                  # LLM integration
│   │       ├── providers.py      # Claude, OpenAI, Local
│   │       └── enhanced_agents.py
│   ├── ml/                       # Machine Learning
│   │   └── anomaly_detector.py   # ML-based anomaly detection
│   ├── compliance/               # Compliance frameworks
│   │   └── frameworks.py         # SOC2, PCI-DSS, HIPAA, etc.
│   ├── storage/                  # Data persistence
│   │   └── database.py           # SQLAlchemy models & storage
│   ├── notifications/            # Alert integrations
│   │   └── webhooks.py           # Slack, generic webhooks
│   ├── remediation/              # Auto-remediation
│   │   └── auto_fix.py           # Automated remediation engine
│   ├── cicd/                     # CI/CD integration
│   │   └── pipeline.py           # GitLab CI, GitHub Actions, Jenkins
│   ├── dashboard/                # Web dashboard
│   │   ├── app.py                # Flask application
│   │   ├── templates/            # HTML templates
│   │   └── static/               # CSS, JS assets
│   ├── enterprise/               # Enterprise features
│   │   ├── rbac.py               # Role-based access control
│   │   ├── cost_analyzer.py      # Cost analysis
│   │   └── threat_intel.py       # Threat intelligence
│   ├── explainers/               # Narrative generation
│   │   ├── narrative_builder.py
│   │   └── aggregation.py
│   ├── reports/                  # Report generation
│   │   ├── json_reporter.py
│   │   ├── markdown_reporter.py
│   │   └── html_reporter.py
│   └── cli/                      # Command-line interface
│       ├── main.py
│       └── commands/
│           ├── scan.py
│           ├── live_scan.py
│           ├── compliance.py
│           ├── generate_example.py
│           └── validate.py
├── examples/                     # Example environments
│   ├── environments/
│   ├── drift_scenarios/
│   └── misconfig_scenarios/
├── schemas/                      # JSON schemas
├── docs/                         # Documentation
├── tests/                        # Test suite
└── README.md                     # This file
```

## Key Components

### Policy Engine

The policy engine evaluates resources against security policies defined in YAML:

```yaml
policies:
  - id: baseline-001
    name: Encryption at Rest Required
    severity: high
    provider: multi
    resource_types:
      - storage
      - database
    condition:
      custom:
        type: encryption
    remediation: |
      Enable encryption at rest for this resource
```

### Detectors

Four specialized detectors identify different types of issues:

1. **Misconfiguration Detector**: Known bad patterns (public access, missing encryption)
2. **Drift Detector**: Configuration changes from baseline
3. **Identity Detector**: IAM/RBAC issues (overprivileged roles, wildcard permissions)
4. **Network Detector**: Network exposure (unrestricted access, public IPs)

### Agentic Components

AI-powered agents provide explanations and guidance:

1. **Misconfiguration Explainer**: Explains what, why, and impact of misconfigurations
2. **Drift Explainer**: Narrates configuration changes and their security implications
3. **Remediation Planner**: Generates step-by-step remediation plans
4. **Risk Summarizer**: Aggregates findings into executive summaries

**LLM Integration**: Supports multiple LLM providers:
- **Claude (Anthropic)**: claude-3-5-sonnet-20241022 and other models
- **OpenAI**: GPT-4, GPT-3.5-turbo
- **Local LLMs**: Ollama and other local models
- **Fallback**: Deterministic implementations when LLM unavailable

Configure LLM provider via environment variables:
```bash
export ANTHROPIC_API_KEY=your_api_key
export OPENAI_API_KEY=your_api_key
```

### Report Formats

- **JSON**: Structured data for programmatic consumption
- **Markdown**: Human-readable reports for documentation
- **HTML**: Interactive dashboards with visualizations

## Example Scenarios

### Demo 1: Baseline Scan

Scan a small AWS environment with intentional security issues:

```bash
# View the environment
ls examples/environments/env_aws_small/runtime_snapshot/

# Run scan
cloudguard-anomaly scan --env examples/environments/env_aws_small

# Expected findings:
# - Public S3 bucket
# - Publicly accessible RDS database
# - Unrestricted SSH/RDP access
# - Overprivileged IAM role
```

### Demo 2: Drift Detection

Detect when a secure bucket was made public:

```bash
cloudguard-anomaly scan --env examples/drift_scenarios/public_bucket_after_change

# Expected anomalies:
# - ACL changed from private to public-read
# - Public access block disabled
# - Security posture degradation detected
```

### Demo 3: Generate Custom Environment

Create your own test environment:

```bash
cloudguard-anomaly generate \
  --name my-custom-env \
  --provider aws \
  --resources 10 \
  --with-issues

cloudguard-anomaly scan --env examples/environments/my-custom-env
```

## Policy Development

### Creating Custom Policies

Create a YAML file with custom policies:

```yaml
policies:
  - id: custom-001
    name: Require Specific Tag
    severity: medium
    provider: aws
    resource_types:
      - storage
    condition:
      exists:
        path: tags.CostCenter
        should_exist: true
    remediation: |
      Add CostCenter tag to resource
```

### Policy Condition Types

- `property_check`: Check property values
- `exists`: Verify property existence
- `pattern`: Regex pattern matching
- `custom`: Custom check functions

## Development

### Running Tests

```bash
pytest
```

### Code Formatting

```bash
black cloudguard_anomaly/
ruff check cloudguard_anomaly/
```

### Type Checking

```bash
mypy cloudguard_anomaly/
```

## Extending CloudGuard-Anomaly

### Adding a New Provider

1. Create provider class inheriting from `BaseProvider`
2. Implement resource type mappings
3. Add provider-specific policies

### Adding a New Detector

1. Create detector class in `detectors/`
2. Implement detection logic
3. Integrate into analysis engine

### Adding a New Agent

1. Inherit from `BaseAgent`
2. Implement `process()` method
3. Return structured output with explanations

### Integrating LLM APIs

To replace deterministic agents with real LLM calls:

1. Implement `_call_llm()` in `BaseAgent`
2. Configure API keys and endpoints
3. Format inputs as prompts using `_format_prompt()`

## Architecture Decisions

### Why Synthetic Environments?

- No dependency on real cloud accounts
- Reproducible testing and demonstrations
- Safe exploration of security issues
- Easy onboarding for new users

### Why Agentic Design?

- Structured for easy LLM integration
- Clear separation of concerns
- Extensible and pluggable architecture
- Future-proof for AI advancements

### Why Provider Abstraction?

- Multi-cloud support
- Consistent security analysis
- Easier to add new providers
- Reusable policies across clouds

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- CIS Benchmarks for security policy references
- Cloud provider documentation
- Open-source security tools community

## Roadmap

### Completed ✅
- [x] Live cloud provider integration (AWS, Azure, GCP)
- [x] LLM integration for agentic components (Claude, OpenAI, Local)
- [x] Machine learning-based anomaly detection (Isolation Forest)
- [x] Compliance frameworks (SOC2, HIPAA, PCI-DSS, ISO 27001)
- [x] CI/CD pipeline integration (GitLab CI, GitHub Actions, Jenkins)
- [x] Webhook notifications (Slack, generic webhooks)
- [x] Database backend for historical tracking (SQLAlchemy)
- [x] Web dashboard for real-time monitoring (Flask + WebSockets)
- [x] Auto-remediation engine with dry-run mode
- [x] RBAC and multi-tenancy support
- [x] Cost analysis and optimization recommendations
- [x] Threat intelligence integration

### Planned 🚀
- [ ] Kubernetes security posture analysis
- [ ] Integration with ticketing systems (Jira, ServiceNow)
- [ ] Container security scanning (Docker, OCI images)
- [ ] Infrastructure as Code scanning (Terraform, CloudFormation)
- [ ] Advanced ML models (deep learning for pattern recognition)
- [ ] Mobile app for notifications and monitoring
- [ ] Advanced reporting (PDF exports, executive dashboards)
- [ ] Multi-region and cross-account analysis
- [ ] Custom integration marketplace
- [ ] SaaS offering with managed deployment

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/nik-kale/CloudGuard-Anomaly/issues
- Documentation: https://github.com/nik-kale/CloudGuard-Anomaly/docs

---

**CloudGuard-Anomaly** - Making cloud security posture analysis accessible, explainable, and actionable.
