# Changelog

## Unreleased

### Fixed

- The dashboard and REST API can start: broken package imports, a missing permission, a
  duplicate database index and forked migrations no longer stop them.
- Login, sessions, API keys and role checks work. Tokens from JSON login are accepted as
  Bearer credentials.
- `scan` reads provider-native resource types and the current state of drift scenarios.
  Previously the bundled examples loaded no resources and reported no issues.
- JSON, Markdown, HTML and PDF reports are generated from scan results.
- `remediate` honours `--severity` by rank and can leave dry-run with `--no-dry-run`.
- `train-ml` trains on stored resources.
- `container-scan` runs and exits 0, 1 or 2 according to its findings.
- Terraform parsing works with current python-hcl2. CloudFormation accepts `!Ref` and `!Sub`.
- Parallel scanning, attack-path analysis, Slack alerts, multi-account scans and encryption and
  logging policy checks return correct results.
- Retention cleanup removes anomalies and compliance records as well as scans and findings.
- The container image runs as its non-root user, and its entry point follows configuration.

### Security

- The dashboard no longer runs in debug mode inside the container and binds to `127.0.0.1` by
  default. Set `DASHBOARD_HOST` to expose it.
- Scanned values are escaped in the dashboard and in HTML and PDF reports.
- Environment names can no longer write reports outside the output directory.
- Login is rate limited to 5 attempts a minute, and failed logins are recorded in the audit log.
- API changes to users, roles and policies are recorded in the audit log.
- CSRF protection covers cookie-authenticated requests, including the login form.
- Passwords and API keys are compared in constant time; common passwords with added digits or
  symbols and sequential runs are rejected.
- Database passwords no longer appear in logs or health responses.
- Request bodies are limited to 1 MiB, and outbound HTTP calls have timeouts.
- `CREATE_ADMIN` now requires `ADMIN_PASSWORD`; the built-in default password is gone.

### Changed

- `DASHBOARD_SECRET_KEY` is required only to start the dashboard, not for CLI scans or migrations.
- PostgreSQL connections use psycopg 3, the default driver for SQLAlchemy 2.1. `requirements.txt`
  now also includes reportlab and jira.
- Wheels include the built-in policies and dashboard templates. Optional features are available as
  `dashboard`, `aws`, `pdf`, `iac` and `ml` extras.
