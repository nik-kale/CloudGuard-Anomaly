# Contributing to CloudGuard-Anomaly

Thank you for your interest in contributing to CloudGuard-Anomaly! This document provides guidelines and instructions for contributing.

## Code of Conduct

Be respectful, inclusive, and professional in all interactions.

## How to Contribute

### Reporting Issues

- Use GitHub Issues to report bugs or request features
- Search existing issues before creating a new one
- Provide clear, detailed descriptions
- Include steps to reproduce for bugs
- Include environment information (OS, Python version)

### Submitting Pull Requests

1. **Fork the Repository**
   ```bash
   git clone https://github.com/<your-username>/CloudGuard-Anomaly.git
   cd CloudGuard-Anomaly
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Your Changes**
   - Write clean, readable code
   - Follow existing code style
   - Add docstrings to functions and classes
   - Update documentation if needed

4. **Add Tests**
   ```bash
   # Add tests in tests/
   pytest tests/
   ```

5. **Run Code Quality Checks**
   ```bash
   # Format code
   black cloudguard_anomaly/

   # Check linting
   ruff check cloudguard_anomaly/

   # Type checking
   mypy cloudguard_anomaly/
   ```

6. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "Add: Brief description of changes"
   ```

   Commit message format:
   - `Add:` for new features
   - `Fix:` for bug fixes
   - `Update:` for modifications
   - `Docs:` for documentation
   - `Test:` for test additions

7. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

8. **Create Pull Request**
   - Go to GitHub and create a pull request
   - Provide clear description of changes
   - Reference related issues
   - Wait for review and address feedback

## Development Setup

### Prerequisites

- Python 3.11 or higher
- Git

### Installation

```bash
# Clone repository
git clone https://github.com/cloudguard-anomaly/CloudGuard-Anomaly.git
cd CloudGuard-Anomaly

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=cloudguard_anomaly --cov-report=html

# Run specific test file
pytest tests/test_engine.py

# Run with verbose output
pytest -v
```

### Code Style

We follow:
- PEP 8 style guide
- 100 character line length
- Type hints for function signatures
- Docstrings for public functions and classes

Use these tools:
```bash
# Format code
black cloudguard_anomaly/

# Check linting
ruff check cloudguard_anomaly/

# Type checking
mypy cloudguard_anomaly/
```

## Contribution Areas

### High Priority

1. **Provider Support**
   - Add support for more cloud providers
   - Enhance existing provider implementations

2. **Detector Enhancements**
   - Add new detection rules
   - Improve existing detectors
   - Add compliance framework checks

3. **LLM Integration**
   - Integrate with OpenAI, Anthropic, or other LLMs
   - Enhance agent explanations
   - Add conversational interfaces

4. **Documentation**
   - Improve documentation
   - Add examples and tutorials
   - Create video walkthroughs

### Medium Priority

5. **Reporting**
   - Enhance HTML reports with charts
   - Add dashboard integrations
   - Create custom report templates

6. **Performance**
   - Optimize detection algorithms
   - Add caching mechanisms
   - Implement parallel processing

### Low Priority

7. **Testing**
   - Increase test coverage
   - Add integration tests
   - Add performance benchmarks

## Adding New Features

### Adding a New Provider

1. Create `cloudguard_anomaly/providers/your_provider.py`
2. Inherit from `BaseProvider`
3. Implement required methods
4. Add provider policies in `cloudguard_anomaly/policies/`
5. Update documentation
6. Add tests

Example:
```python
from cloudguard_anomaly.providers.base import BaseProvider
from cloudguard_anomaly.core.models import Provider, Resource, ResourceType

class MyCloudProvider(BaseProvider):
    def __init__(self):
        super().__init__("mycloud")

    def get_resource_type_mapping(self):
        return {
            "mycloud_vm": ResourceType.COMPUTE,
            "mycloud_storage": ResourceType.STORAGE,
        }

    def normalize_resource(self, raw_resource):
        # Implement normalization
        pass

    def validate_resource(self, resource):
        # Implement validation
        return []
```

### Adding a New Detector

1. Create `cloudguard_anomaly/detectors/your_detector.py`
2. Implement `detect(resources)` method
3. Return list of `Finding` objects
4. Integrate into `AnalysisEngine`
5. Add tests

Example:
```python
from cloudguard_anomaly.core.models import Finding, FindingType, Severity

class MyDetector:
    def detect(self, resources):
        findings = []
        for resource in resources:
            if self._check_issue(resource):
                finding = Finding(
                    id=f"my-{uuid.uuid4()}",
                    type=FindingType.MISCONFIGURATION,
                    severity=Severity.HIGH,
                    title="Issue Found",
                    description="Description of issue",
                    resource=resource,
                    policy=None,
                    remediation="How to fix",
                )
                findings.append(finding)
        return findings
```

### Adding New Policies

Create YAML file in `cloudguard_anomaly/policies/`:

```yaml
policies:
  - id: custom-001
    name: My Custom Policy
    severity: high
    provider: aws
    resource_types:
      - storage
    condition:
      property_check:
        path: my_property
        operator: equals
        value: bad_value
    remediation: |
      Fix the issue by...
    references:
      - https://docs.example.com
```

## Documentation

- Update README.md for major features
- Add docstrings to all public functions
- Update docs/ for architectural changes
- Include usage examples

## Review Process

1. Maintainers review pull requests
2. Feedback provided within 1 week
3. Address review comments
4. Approval required from at least one maintainer
5. CI checks must pass
6. Squash and merge

## Questions?

- Open an issue for questions
- Join discussions in GitHub Discussions
- Email: (contact information)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to CloudGuard-Anomaly!
