# Grafana Dashboards for CloudGuard-Anomaly

Professional Grafana dashboards for monitoring CloudGuard-Anomaly security scans, SLI/SLO metrics, and operational health.

## Available Dashboards

### 1. Security Posture Overview
**File:** `dashboards/security-posture-overview.json`

Provides comprehensive view of security posture across your infrastructure.

**Panels:**
- Risk Score (0-100 scale with color thresholds)
- Total Findings counter
- Critical Findings alert
- Scans in last 24 hours
- Findings trend by severity (time series)
- Findings distribution by type (pie chart)
- Top 10 resources with most findings
- Scan duration metrics

**Metrics Used:**
- `cloudguard_risk_score`
- `cloudguard_findings_total{severity}`
- `cloudguard_scans_total`
- `cloudguard_scan_duration_seconds`

### 2. SLI/SLO Dashboard
**File:** `dashboards/sli-slo-dashboard.json`

Site Reliability Engineering dashboard for tracking Service Level Indicators and Objectives.

**Key SLIs:**
- **Scan Success Rate:** % of successful scans (SLO: 99.5%)
- **Finding Detection Rate:** % of critical findings detected within 1 hour (SLO: 99%)
- **API Availability:** % of successful API requests (SLO: 99.9%)
- **Scan Performance:** % of scans completing within 5 minutes (SLO: 95%)

**Panels:**
- SLI compliance gauges
- Error budget burn rate
- Mean Time to Detect (MTTD) for critical/high findings
- Error budget remaining (monthly)
- SLO compliance summary table
- Violation annotations

## Installation

### Prerequisites

```bash
# Prometheus must be configured as datasource
# CloudGuard-Anomaly must expose /metrics endpoint
```

### Import Dashboards

#### Via Grafana UI

1. Log into Grafana
2. Navigate to **Dashboards** → **Import**
3. Upload JSON file or paste JSON content
4. Select Prometheus datasource
5. Click **Import**

#### Via API

```bash
# Import Security Posture Overview
curl -X POST http://localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d @dashboards/security-posture-overview.json

# Import SLI/SLO Dashboard
curl -X POST http://localhost:3000/api/dashboards/db \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d @dashboards/sli-slo-dashboard.json
```

#### Via Provisioning

Add to Grafana provisioning configuration:

```yaml
# /etc/grafana/provisioning/dashboards/cloudguard.yaml
apiVersion: 1

providers:
  - name: 'CloudGuard'
    orgId: 1
    folder: 'Security'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    options:
      path: /path/to/grafana/dashboards
```

## Prometheus Configuration

Ensure CloudGuard-Anomaly metrics are being scraped:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'cloudguard-anomaly'
    static_configs:
      - targets: ['cloudguard:5000']
    metrics_path: '/metrics'
    scrape_interval: 30s
```

## Alerting Rules

Create Prometheus alerting rules for SLO violations:

```yaml
# cloudguard-alerts.yml
groups:
  - name: cloudguard_slo
    rules:
      - alert: ScanSuccessRateLow
        expr: |
          (sum(rate(cloudguard_scans_total{status="success"}[5m])) 
           / sum(rate(cloudguard_scans_total[5m]))) < 0.995
        for: 10m
        labels:
          severity: warning
          slo: scan_success_rate
        annotations:
          summary: "Scan success rate below SLO"
          description: "Success rate is {{ $value | humanizePercentage }}"
      
      - alert: CriticalFindingsDetectionSlow
        expr: |
          avg(cloudguard_detection_time_seconds{severity="critical"}) > 3600
        for: 15m
        labels:
          severity: critical
          slo: detection_time
        annotations:
          summary: "Critical findings detection time exceeds 1 hour"
          description: "MTTD is {{ $value | humanizeDuration }}"
      
      - alert: ErrorBudgetExhausted
        expr: |
          ((0.005 - (1 - sum(rate(cloudguard_scans_total{status="success"}[30d])) 
          / sum(rate(cloudguard_scans_total[30d])))) / 0.005) < 0.1
        for: 1h
        labels:
          severity: critical
          slo: error_budget
        annotations:
          summary: "Error budget critically low"
          description: "Only {{ $value | humanizePercentage }} remaining"
```

## Metrics Reference

### Core Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `cloudguard_risk_score` | Gauge | Overall risk score (0-100) |
| `cloudguard_scans_total` | Counter | Total scans by status |
| `cloudguard_scan_duration_seconds` | Histogram | Scan duration distribution |
| `cloudguard_findings_total` | Counter | Findings by severity/type |
| `cloudguard_api_requests_total` | Counter | API requests by endpoint/status |
| `cloudguard_detection_time_seconds` | Histogram | Time to detect findings |
| `cloudguard_active_users` | Gauge | Currently active users |
| `cloudguard_database_connections` | Gauge | Active DB connections |

### Labels

- `severity`: critical, high, medium, low
- `status`: success, failed, timeout
- `type`: misconfiguration, drift, identity, network
- `environment`: environment name
- `provider`: AWS, Azure, GCP

## Customization

### Modify Thresholds

Edit SLO thresholds in dashboard JSON:

```json
"thresholds": {
  "steps": [
    {"value": 0, "color": "red"},      // Below SLO
    {"value": 99.5, "color": "yellow"}, // Warning
    {"value": 99.9, "color": "green"}   // Meets SLO
  ]
}
```

### Add Custom Panels

Use Grafana's panel editor to add:
- Compliance framework breakdown
- Cost impact of findings
- Remediation time tracking
- Team/resource owner metrics

### Variables

Add dashboard variables for filtering:

```json
"templating": {
  "list": [
    {
      "name": "environment",
      "type": "query",
      "query": "label_values(cloudguard_findings_total, environment)"
    },
    {
      "name": "severity",
      "type": "custom",
      "options": ["critical", "high", "medium", "low"]
    }
  ]
}
```

## Best Practices

1. **Set Realistic SLOs**: Start with achievable targets and improve over time
2. **Monitor Error Budget**: Track burn rate to avoid SLO violations
3. **Alert Fatigue**: Configure appropriate thresholds to minimize false positives
4. **Dashboard Organization**: Group related panels for better readability
5. **Regular Review**: Update dashboards based on operational needs

## Troubleshooting

### No Data Showing

- Verify Prometheus is scraping CloudGuard metrics endpoint
- Check metric names match dashboard queries
- Ensure data retention allows for time range selected

### Incorrect Values

- Validate Prometheus queries in Prometheus UI
- Check label names and values
- Verify metric types (Counter vs Gauge vs Histogram)

### Dashboard Import Errors

- Ensure JSON is valid (use jsonlint.com)
- Check Grafana version compatibility
- Verify datasource UID matches your Prometheus instance

## Support

For issues or enhancements:
- GitHub Issues: https://github.com/cloudguard-anomaly/cloudguard-anomaly/issues
- Documentation: See main README.md

## License

MIT License - See LICENSE file for details

