# CloudGuard-Anomaly Kubernetes Deployment

This directory contains production-ready Kubernetes manifests for deploying CloudGuard-Anomaly v3.0.

## Architecture

```
┌─────────────────┐
│   Ingress       │ (NGINX with TLS, rate limiting, security headers)
└────────┬────────┘
         │
┌────────▼────────┐
│   Service       │ (ClusterIP with session affinity)
└────────┬────────┘
         │
┌────────▼────────────────────┐
│   Deployment (3-10 replicas)│ (Auto-scaling, rolling updates)
│   - CloudGuard-Anomaly      │
│   - Health checks           │
│   - Resource limits         │
└──┬────────────────┬─────────┘
   │                │
┌──▼──────┐    ┌───▼──────┐
│PostgreSQL│    │  Redis   │
│(StatefulSet)  │(Deployment)
└──────────┘    └──────────┘
```

## Prerequisites

- Kubernetes cluster 1.24+
- kubectl configured
- NGINX Ingress Controller
- cert-manager (optional, for TLS)
- Metrics Server (for HPA)
- Kustomize (optional)

## Quick Start

### 1. Update Configuration

Edit `base/secret.yaml` and `base/configmap.yaml` with your values:

```bash
# Generate a secure secret key
python -c "import secrets; print(secrets.token_hex(32))"

# Update secret.yaml
kubectl create secret generic cloudguard-secrets \
  --from-literal=DASHBOARD_SECRET_KEY="your-secret-key" \
  --from-literal=POSTGRES_PASSWORD="your-db-password" \
  --dry-run=client -o yaml > base/secret.yaml
```

### 2. Update Image Reference

Edit `base/deployment.yaml` and replace `NAMESPACE` with your container registry namespace:

```yaml
image: ghcr.io/YOUR-USERNAME/cloudguard-anomaly:latest
```

### 3. Deploy

Using kubectl:
```bash
kubectl apply -f base/
```

Using kustomize:
```bash
kubectl apply -k base/
```

### 4. Verify Deployment

```bash
# Check pod status
kubectl get pods -n cloudguard

# Check service
kubectl get svc -n cloudguard

# Check ingress
kubectl get ingress -n cloudguard

# View logs
kubectl logs -n cloudguard -l app=cloudguard-anomaly --tail=100
```

### 5. Access the Application

```bash
# Port-forward (for testing)
kubectl port-forward -n cloudguard svc/cloudguard-anomaly 5000:80

# Visit http://localhost:5000
```

For production, configure DNS to point to your Ingress controller's external IP.

## Components

### Core Application

- **Deployment**: 3-10 replicas with auto-scaling
- **Service**: ClusterIP with session affinity
- **Ingress**: TLS, rate limiting, security headers
- **HPA**: CPU/memory-based auto-scaling
- **PDB**: Ensures minimum 2 replicas during disruptions

### Database

- **PostgreSQL StatefulSet**: Single replica with persistent storage
- **PVC**: 20Gi storage for database
- **Service**: Headless service for StatefulSet

### Cache

- **Redis Deployment**: Single replica for caching and rate limiting
- **Service**: ClusterIP service

### Security

- **NetworkPolicy**: Restricts pod-to-pod communication
- **RBAC**: Minimal permissions for service account
- **SecurityContext**: Runs as non-root user
- **Secret**: Encrypted credentials

## Configuration

### Environment Variables

Configured via ConfigMap (`base/configmap.yaml`):

- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `CORS_ORIGINS`: Allowed CORS origins
- `RATE_LIMIT_ENABLED`: Enable rate limiting
- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)

### Secrets

Configured via Secret (`base/secret.yaml`):

- `DASHBOARD_SECRET_KEY`: Flask secret key
- `POSTGRES_PASSWORD`: Database password
- Cloud provider credentials (AWS, Azure, GCP)
- LLM API keys (Anthropic, OpenAI)

## Scaling

### Manual Scaling

```bash
kubectl scale deployment cloudguard-anomaly -n cloudguard --replicas=5
```

### Auto-Scaling

HPA is configured to scale based on:
- CPU utilization (target: 70%)
- Memory utilization (target: 80%)
- Min replicas: 3
- Max replicas: 10

Modify `base/hpa.yaml` to adjust scaling parameters.

## Monitoring

### Health Checks

- **Liveness**: `/health` endpoint, checks if application is alive
- **Readiness**: `/health` endpoint, checks if application is ready to serve traffic

### Prometheus Metrics

The deployment includes Prometheus annotations:

```yaml
prometheus.io/scrape: "true"
prometheus.io/port: "5000"
prometheus.io/path: "/metrics"
```

Create a ServiceMonitor:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: cloudguard-anomaly
  namespace: cloudguard
spec:
  selector:
    matchLabels:
      app: cloudguard-anomaly
  endpoints:
  - port: http
    path: /metrics
```

## Backup and Recovery

### Database Backup

```bash
# Create backup
kubectl exec -n cloudguard postgres-0 -- pg_dump -U cloudguard cloudguard > backup.sql

# Restore backup
kubectl exec -i -n cloudguard postgres-0 -- psql -U cloudguard cloudguard < backup.sql
```

### Automated Backups

Use a CronJob:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgres-backup
  namespace: cloudguard
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: postgres:15-alpine
            command:
            - /bin/sh
            - -c
            - pg_dump -h postgres -U cloudguard cloudguard | gzip > /backup/backup-$(date +%Y%m%d).sql.gz
            volumeMounts:
            - name: backup
              mountPath: /backup
          volumes:
          - name: backup
            persistentVolumeClaim:
              claimName: backup-pvc
          restartPolicy: OnFailure
```

## Troubleshooting

### Pods Not Starting

```bash
# Check pod events
kubectl describe pod -n cloudguard <pod-name>

# Check logs
kubectl logs -n cloudguard <pod-name>

# Check init containers
kubectl logs -n cloudguard <pod-name> -c wait-for-postgres
kubectl logs -n cloudguard <pod-name> -c db-migrate
```

### Database Connection Issues

```bash
# Test PostgreSQL connection
kubectl exec -it -n cloudguard postgres-0 -- psql -U cloudguard

# Check PostgreSQL logs
kubectl logs -n cloudguard postgres-0
```

### Ingress Issues

```bash
# Check ingress status
kubectl describe ingress -n cloudguard cloudguard-anomaly

# Check ingress controller logs
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx
```

## Production Checklist

- [ ] Update all passwords and secret keys
- [ ] Configure TLS certificates
- [ ] Set up DNS for your domain
- [ ] Configure persistent storage class
- [ ] Set up monitoring (Prometheus, Grafana)
- [ ] Set up logging (EFK stack)
- [ ] Configure backup strategy
- [ ] Set resource requests and limits
- [ ] Configure network policies
- [ ] Set up alerting
- [ ] Document disaster recovery procedures
- [ ] Perform load testing
- [ ] Set up CI/CD pipeline
- [ ] Configure audit logging retention

## Updates and Rollbacks

### Rolling Update

```bash
# Update image
kubectl set image deployment/cloudguard-anomaly \
  cloudguard-anomaly=ghcr.io/NAMESPACE/cloudguard-anomaly:v3.1 \
  -n cloudguard

# Check rollout status
kubectl rollout status deployment/cloudguard-anomaly -n cloudguard
```

### Rollback

```bash
# Rollback to previous version
kubectl rollout undo deployment/cloudguard-anomaly -n cloudguard

# Rollback to specific revision
kubectl rollout undo deployment/cloudguard-anomaly --to-revision=2 -n cloudguard
```

## Support

For issues and questions:
- GitHub Issues: https://github.com/YOUR-ORG/CloudGuard-Anomaly/issues
- Documentation: https://docs.cloudguard.example.com
