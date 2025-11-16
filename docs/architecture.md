# CloudGuard-Anomaly Architecture

## Overview

CloudGuard-Anomaly is designed as a modular, extensible framework for cloud security posture analysis and anomaly detection. This document describes the high-level architecture and design decisions.

## Core Components

### 1. Data Models (`core/models.py`)

All data structures inherit from Python dataclasses for type safety and serialization:

- **Resource**: Represents a cloud resource (compute, storage, network, etc.)
- **Policy**: Defines a security rule or check
- **Finding**: Represents a discovered security issue
- **Anomaly**: Represents detected configuration drift
- **Environment**: Collection of resources representing a cloud environment
- **ScanResult**: Complete results of a security scan

### 2. Provider Abstraction (`providers/`)

Provider abstraction allows CloudGuard to work across multiple clouds:

```
BaseProvider (abstract)
    ├── AWSProvider
    ├── AzureProvider
    └── GCPProvider
```

Each provider implements:
- Resource type mapping (provider-specific → standard types)
- Resource normalization (provider format → standard Resource model)
- Validation logic

### 3. Analysis Engine (`core/engine.py`)

The analysis engine orchestrates the entire security analysis pipeline:

```
Input: Environment + Policies
    ↓
Policy Evaluation
    ↓
Detector Modules (parallel)
    ├── Misconfiguration Detector
    ├── Drift Detector
    ├── Identity Detector
    └── Network Detector
    ↓
Agentic Explanation
    ↓
Output: ScanResult
```

### 4. Detection Modules (`detectors/`)

Four specialized detectors identify different security issues:

**MisconfigDetector**
- Pattern-based detection
- Known bad configurations
- Resource-specific checks

**DriftDetector**
- Baseline comparison
- Change identification
- Security degradation analysis

**IdentityDetector**
- IAM permission analysis
- Privilege escalation risks
- Cross-account access

**NetworkDetector**
- Public exposure detection
- Security group analysis
- Port-based risk assessment

### 5. Agentic Components (`agents/`)

AI-powered agents generate human-readable explanations:

```
BaseAgent (abstract)
    ├── MisconfigExplainerAgent
    ├── DriftExplainerAgent
    ├── RemediationPlannerAgent
    └── RiskSummarizerAgent
```

**Design Note**: Current implementation uses deterministic logic but is structured for easy LLM integration. Each agent has:
- Structured input/output interfaces
- Prompt formatting methods (for future LLM use)
- Pure-Python fallback implementations

### 6. Reporting (`reports/`)

Multiple output formats for different audiences:

- **JSONReporter**: Machine-readable structured data
- **MarkdownReporter**: Human-readable documentation
- **HTMLReporter**: Interactive dashboards

## Data Flow

### 1. Loading Phase

```
Environment Directory
    ├── environment.yaml      (metadata)
    ├── runtime_snapshot/     (current configs)
    └── baseline/             (baseline configs, optional)
    ↓
ConfigLoader
    ↓
Environment Object (with Resources)
```

### 2. Analysis Phase

```
Environment + Policies
    ↓
PolicyEvaluator.evaluate_resources()
    ↓
Detector Modules (concurrent)
    ↓
Findings + Anomalies
```

### 3. Explanation Phase

```
Findings + Anomalies
    ↓
Agentic Explainers
    ↓
Narratives (human-readable explanations)
```

### 4. Reporting Phase

```
ScanResult
    ↓
Reporters (JSONReporter, MarkdownReporter, HTMLReporter)
    ↓
Output Files
```

## Policy Engine

### Policy Structure

```yaml
policies:
  - id: unique-id
    name: Human-readable name
    severity: critical|high|medium|low|info
    provider: aws|azure|gcp|multi
    resource_types: [list]
    condition: {evaluation logic}
    remediation: "How to fix"
    references: [external refs]
```

### Condition Types

1. **property_check**: Check resource property values
2. **exists**: Verify property existence
3. **pattern**: Regex pattern matching
4. **custom**: Custom check functions

## Extension Points

### Adding New Providers

1. Create class inheriting from `BaseProvider`
2. Implement `get_resource_type_mapping()`
3. Implement `normalize_resource()`
4. Add provider-specific policies

### Adding New Detectors

1. Create detector class in `detectors/`
2. Implement `detect(resources)` method
3. Return list of `Finding` objects
4. Integrate into `AnalysisEngine.scan_environment()`

### Adding New Agents

1. Inherit from `BaseAgent`
2. Implement `process(input_data)` method
3. Return structured output with explanations

### Integrating LLMs

To replace deterministic agents with LLM calls:

```python
class MisconfigExplainerAgent(BaseAgent):
    def _call_llm(self, prompt: str) -> str:
        # Add your LLM integration here
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
```

## Design Principles

### 1. Provider Abstraction
- Uniform security analysis across clouds
- Shared policies where possible
- Provider-specific optimizations

### 2. Separation of Concerns
- Detection: Find issues
- Explanation: Describe issues
- Remediation: Fix issues

### 3. Extensibility
- Plugin architecture for detectors
- Configurable policy engine
- Modular agent design

### 4. Deterministic Core + AI Enhancement
- Core logic is deterministic and testable
- AI agents add explanatory value
- Graceful degradation without AI

### 5. Structured Data
- Type-safe models
- JSON schema validation
- Clear contracts between components

## Performance Considerations

### Concurrency
- Detector modules can run in parallel
- Resource evaluation is parallelizable
- Future: Async/await for I/O operations

### Caching
- Policy loading cached per engine instance
- Provider mappings cached
- Future: Resource data caching

### Scalability
- Designed for 100s-1000s of resources per environment
- Streaming processing for large environments (future)
- Distributed analysis (future)

## Security Considerations

- No cloud credentials required (works on snapshots)
- No external API calls by default
- Sensitive data handled in memory only
- Reports can be sanitized before distribution

## Testing Strategy

- Unit tests for core components
- Integration tests for end-to-end flows
- Synthetic environments for reproducible testing
- No dependency on real cloud accounts

## Future Enhancements

1. **Real-time Monitoring**: Stream from cloud APIs
2. **ML-based Anomaly Detection**: Learn normal patterns
3. **Remediation Automation**: Auto-fix common issues
4. **Compliance Frameworks**: SOC2, HIPAA, PCI-DSS
5. **LLM Integration**: Replace deterministic agents
6. **Distributed Analysis**: Scale to large cloud estates
