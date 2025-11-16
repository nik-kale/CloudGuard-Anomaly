"""
OpenAPI/Swagger configuration for CloudGuard-Anomaly API.
"""

SWAGGER_CONFIG = {
    'title': 'CloudGuard-Anomaly API',
    'version': '3.0',
    'description': '''
# CloudGuard-Anomaly API Documentation

CloudGuard-Anomaly is a comprehensive cloud security posture management and anomaly detection platform.

## Features

- **Multi-Cloud Support**: AWS, Azure, GCP
- **Security Scanning**: Misconfiguration detection, compliance checks
- **Anomaly Detection**: ML-powered behavioral analysis
- **RBAC**: Role-based access control with granular permissions
- **Audit Logging**: Complete audit trail for compliance
- **Real-time Monitoring**: WebSocket-based live updates

## Authentication

All API endpoints require authentication using one of the following methods:

### Session-Based Authentication
1. Login via `POST /login` with username/password
2. Receive session cookie
3. Include cookie in subsequent requests

### API Key Authentication
1. Generate API key via `POST /api/auth/generate-api-key`
2. Include in `Authorization: Bearer <api-key>` header
3. Or include in `X-API-Key: <api-key>` header

## Rate Limiting

API endpoints are rate-limited to prevent abuse:
- Default: 100 requests per hour per IP
- Login endpoint: 10 requests per minute per IP
- API key generation: 3 requests per hour per user

## Response Format

All API responses follow a consistent JSON format:

### Success Response
```json
{
  "data": {...},
  "count": 10,
  "limit": 100,
  "offset": 0
}
```

### Error Response
```json
{
  "error": "Error message",
  "request_id": "uuid-v4"
}
```

## Permissions

Different endpoints require different permissions:

- `scan:*` - Scan operations
- `finding:*` - Finding operations
- `policy:*` - Policy management
- `user:*` - User management
- `role:*` - Role management
- `audit:*` - Audit log access
- `compliance:*` - Compliance operations
- `admin:*` - Administrative operations

## Support

- Documentation: https://docs.cloudguard.example.com
- GitHub: https://github.com/YOUR-ORG/CloudGuard-Anomaly
- Issues: https://github.com/YOUR-ORG/CloudGuard-Anomaly/issues
    ''',
    'termsOfService': 'https://cloudguard.example.com/terms',
    'contact': {
        'name': 'CloudGuard Support',
        'email': 'support@cloudguard.example.com',
        'url': 'https://cloudguard.example.com/support'
    },
    'license': {
        'name': 'MIT',
        'url': 'https://opensource.org/licenses/MIT'
    },
    'specs_route': '/api/docs/',
    'openapi': '3.0.3',
    'headers': [],
    'specs': [
        {
            'endpoint': 'apispec',
            'route': '/api/docs/apispec.json',
            'rule_filter': lambda rule: True,
            'model_filter': lambda tag: True,
        }
    ],
    'static_url_path': '/flasgger_static',
    'swagger_ui': True,
    'specs_route': '/api/docs/'
}

SWAGGER_TEMPLATE = {
    'securityDefinitions': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'in': 'header',
            'description': 'API Key authentication. Format: "Bearer <api-key>"'
        },
        'ApiKey': {
            'type': 'apiKey',
            'name': 'X-API-Key',
            'in': 'header',
            'description': 'API Key authentication via X-API-Key header'
        }
    },
    'security': [
        {'Bearer': []},
        {'ApiKey': []}
    ],
    'tags': [
        {
            'name': 'Authentication',
            'description': 'User authentication and session management'
        },
        {
            'name': 'Policies',
            'description': 'Security policy management'
        },
        {
            'name': 'Users',
            'description': 'User account management'
        },
        {
            'name': 'Roles',
            'description': 'Role and permission management'
        },
        {
            'name': 'Audit Logs',
            'description': 'Audit trail and compliance logging'
        },
        {
            'name': 'Scans',
            'description': 'Security scan management'
        },
        {
            'name': 'Findings',
            'description': 'Security finding management'
        },
        {
            'name': 'Compliance',
            'description': 'Compliance framework assessment'
        }
    ]
}
