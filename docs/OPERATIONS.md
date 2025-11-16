# CloudGuard-Anomaly Operations Guide

Complete operational runbook for production deployment and maintenance.

## Table of Contents

1. [Deployment](#deployment)
2. [Backup and Restore](#backup-and-restore)
3. [Monitoring](#monitoring)
4. [Troubleshooting](#troubleshooting)
5. [Scaling](#scaling)
6. [Security](#security)
7. [Maintenance](#maintenance)

---

## Deployment

### Prerequisites

- Kubernetes 1.24+ cluster
- PostgreSQL 15+ (or use included manifest)
- Redis 7+ (or use included manifest)
- kubectl configured
- NGINX Ingress Controller
- cert-manager (optional, for TLS)

### Initial Deployment

1. **Clone Repository**
```bash
git clone https://github.com/YOUR-ORG/CloudGuard-Anomaly.git
cd CloudGuard-Anomaly
```

2. **Configure Secrets**
```bash
# Generate secure secret key
python -c "import secrets; print(secrets.token_hex(32))"

# Create secrets
kubectl create secret generic cloudguard-secrets \
  --from-literal=DASHBOARD_SECRET_KEY="your-generated-key" \
  --from-literal=POSTGRES_PASSWORD="strong-database-password" \
  --namespace=cloudguard
```

3. **Deploy Infrastructure**
```bash
# Create namespace
kubectl apply -f k8s/base/namespace.yaml

# Deploy PostgreSQL
kubectl apply -f k8s/base/postgres.yaml

# Deploy Redis
kubectl apply -f k8s/base/redis.yaml

# Wait for databases to be ready
kubectl wait --for=condition=ready pod -l app=postgres -n cloudguard --timeout=300s
kubectl wait --for=condition=ready pod -l app=redis -n cloudguard --timeout=300s
```

4. **Deploy Application**
```bash
# Apply all manifests
kubectl apply -f k8s/base/

# Watch rollout
kubectl rollout status deployment/cloudguard-anomaly -n cloudguard
```

5. **Verify Deployment**
```bash
# Check pods
kubectl get pods -n cloudguard

# Check services
kubectl get svc -n cloudguard

# Check ingress
kubectl get ingress -n cloudguard

# Test health endpoint
kubectl port-forward svc/cloudguard-anomaly 5000:80 -n cloudguard
curl http://localhost:5000/health
```

### Updating Deployment

```bash
# Update image
kubectl set image deployment/cloudguard-anomaly \
  cloudguard-anomaly=ghcr.io/YOUR-ORG/cloudguard-anomaly:v3.1 \
  -n cloudguard

# Or apply updated manifests
kubectl apply -f k8s/base/deployment.yaml

# Monitor rollout
kubectl rollout status deployment/cloudguard-anomaly -n cloudguard

# Rollback if needed
kubectl rollout undo deployment/cloudguard-anomaly -n cloudguard
```

---

## Backup and Restore

### Database Backup

#### Manual Backup

```bash
# Backup PostgreSQL
kubectl exec -n cloudguard postgres-0 -- pg_dump -U cloudguard cloudguard \
  | gzip > backup-$(date +%Y%m%d-%H%M%S).sql.gz

# Verify backup
gunzip -c backup-*.sql.gz | head -n 20
```

#### Automated Backup (CronJob)

Create `backup-cronjob.yaml`:
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgres-backup
  namespace: cloudguard
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  successfulJobsHistoryLimit: 7
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: postgres:15-alpine
            env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: cloudguard-secrets
                  key: POSTGRES_PASSWORD
            command:
            - /bin/sh
            - -c
            - |
              pg_dump -h postgres -U cloudguard cloudguard | \
              gzip > /backup/backup-$(date +%Y%m%d-%H%M%S).sql.gz
            volumeMounts:
            - name: backup
              mountPath: /backup
          volumes:
          - name: backup
            persistentVolumeClaim:
              claimName: backup-pvc
          restartPolicy: OnFailure
```

Apply with:
```bash
kubectl apply -f backup-cronjob.yaml
```

### Restore from Backup

```bash
# Copy backup to pod
kubectl cp backup-20251116.sql.gz cloudguard/postgres-0:/tmp/

# Restore
kubectl exec -it -n cloudguard postgres-0 -- bash
gunzip -c /tmp/backup-20251116.sql.gz | psql -U cloudguard cloudguard
```

### Disaster Recovery

1. **Full Cluster Failure**
```bash
# Deploy new cluster
kubectl apply -f k8s/base/namespace.yaml
kubectl apply -f k8s/base/postgres.yaml

# Wait for PostgreSQL
kubectl wait --for=condition=ready pod -l app=postgres -n cloudguard --timeout=300s

# Restore database
kubectl cp backup-latest.sql.gz cloudguard/postgres-0:/tmp/
kubectl exec -it -n cloudguard postgres-0 -- \
  bash -c "gunzip -c /tmp/backup-latest.sql.gz | psql -U cloudguard cloudguard"

# Deploy application
kubectl apply -f k8s/base/
```

2. **Data Corruption**
```bash
# Stop application
kubectl scale deployment cloudguard-anomaly --replicas=0 -n cloudguard

# Restore database (see above)

# Start application
kubectl scale deployment cloudguard-anomaly --replicas=3 -n cloudguard
```

---

## Monitoring

### Health Checks

```bash
# Application health
curl https://cloudguard.example.com/health

# Detailed component status
kubectl exec -n cloudguard deploy/cloudguard-anomaly -- \
  curl -s localhost:5000/health | jq

# Check logs
kubectl logs -n cloudguard -l app=cloudguard-anomaly --tail=100
```

### Prometheus Metrics

```bash
# View metrics
curl https://cloudguard.example.com/metrics

# Key metrics to monitor:
# - cloudguard_http_requests_total
# - cloudguard_http_request_duration_seconds
# - cloudguard_scans_total
# - cloudguard_findings_open
# - cloudguard_errors_total
```

### Grafana Dashboards

Import dashboards from `/monitoring/dashboards/`:
- `application-overview.json` - Application metrics
- `security-metrics.json` - Security findings and scans
- `system-metrics.json` - Resource usage

### Alerts

Critical alerts to configure:

```yaml
# High error rate
- alert: HighErrorRate
  expr: rate(cloudguard_errors_total[5m]) > 10
  for: 5m
  annotations:
    summary: "High error rate detected"

# Database connection issues  
- alert: DatabaseConnectionFailed
  expr: cloudguard_db_connections_total{state="active"} == 0
  for: 1m
  annotations:
    summary: "Database connection failed"

# Pod restarts
- alert: PodRestarting
  expr: rate(kube_pod_container_status_restarts_total{namespace="cloudguard"}[15m]) > 0
  for: 5m
  annotations:
    summary: "Pod is restarting frequently"
```

---

## Troubleshooting

### Common Issues

#### Pods Not Starting

```bash
# Check pod events
kubectl describe pod -n cloudguard <pod-name>

# Check logs
kubectl logs -n cloudguard <pod-name>

# Check init containers
kubectl logs -n cloudguard <pod-name> -c wait-for-postgres
kubectl logs -n cloudguard <pod-name> -c db-migrate

# Common causes:
# 1. Database not ready - wait longer
# 2. Migration failure - check alembic logs
# 3. Image pull error - check registry auth
# 4. Resource limits - check node capacity
```

#### Database Connection Errors

```bash
# Test database connectivity
kubectl exec -it -n cloudguard postgres-0 -- psql -U cloudguard

# Check database status
kubectl logs -n cloudguard postgres-0

# Verify service
kubectl get svc postgres -n cloudguard

# Test from application pod
kubectl exec -it -n cloudguard deploy/cloudguard-anomaly -- \
  pg_isready -h postgres -p 5432
```

#### High Memory Usage

```bash
# Check resource usage
kubectl top pods -n cloudguard

# Increase memory limits
kubectl set resources deployment cloudguard-anomaly \
  --limits=memory=4Gi -n cloudguard

# Check for memory leaks in logs
kubectl logs -n cloudguard -l app=cloudguard-anomaly | grep -i "memory\|oom"
```

#### Slow Performance

```bash
# Check database query performance
kubectl exec -it -n cloudguard postgres-0 -- psql -U cloudguard cloudguard
SELECT * FROM pg_stat_statements ORDER BY total_time DESC LIMIT 10;

# Check cache hit rate
curl http://localhost:5000/metrics | grep cache

# Scale horizontally
kubectl scale deployment cloudguard-anomaly --replicas=5 -n cloudguard
```

### Debug Mode

Enable debug logging:
```bash
kubectl set env deployment/cloudguard-anomaly LOG_LEVEL=DEBUG -n cloudguard
```

### Request Tracing

All requests include `X-Request-ID` header for tracing:
```bash
# Find all logs for a specific request
kubectl logs -n cloudguard -l app=cloudguard-anomaly | grep "request_id_here"
```

---

## Scaling

### Horizontal Scaling

#### Manual Scaling
```bash
# Scale to specific replicas
kubectl scale deployment cloudguard-anomaly --replicas=5 -n cloudguard

# Verify
kubectl get pods -n cloudguard -l app=cloudguard-anomaly
```

#### Auto-Scaling (HPA)
```bash
# HPA is pre-configured in k8s/base/hpa.yaml
# Scales 3-10 replicas based on:
# - CPU utilization > 70%
# - Memory utilization > 80%

# Check HPA status
kubectl get hpa -n cloudguard

# Modify scaling thresholds
kubectl edit hpa cloudguard-anomaly -n cloudguard
```

### Vertical Scaling

```bash
# Increase CPU and memory
kubectl set resources deployment cloudguard-anomaly \
  --requests=cpu=1000m,memory=1Gi \
  --limits=cpu=2000m,memory=4Gi \
  -n cloudguard
```

### Database Scaling

PostgreSQL is deployed as StatefulSet with single replica. For production:

1. **Use Managed Database** (recommended)
   - AWS RDS for PostgreSQL
   - Azure Database for PostgreSQL
   - Google Cloud SQL for PostgreSQL

2. **Deploy PostgreSQL Cluster**
   - Use operators like CloudNativePG or Crunchy Postgres Operator
   - Configure replication and failover

---

## Security

### Secrets Management

#### Rotate Secrets

```bash
# Generate new dashboard secret key
NEW_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# Update secret
kubectl create secret generic cloudguard-secrets \
  --from-literal=DASHBOARD_SECRET_KEY="$NEW_KEY" \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart pods to pick up new secret
kubectl rollout restart deployment/cloudguard-anomaly -n cloudguard
```

#### Use External Secrets Operator

For production, use External Secrets Operator with:
- AWS Secrets Manager
- Azure Key Vault
- Google Secret Manager
- HashiCorp Vault

### Network Policies

Network policies are configured to restrict pod-to-pod communication:

```bash
# Verify network policies
kubectl get networkpolicies -n cloudguard

# Test connectivity
kubectl run test -it --rm --image=busybox -n cloudguard -- \
  wget -O- http://postgres:5432
```

### TLS/HTTPS

Configure TLS using cert-manager:

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Create ClusterIssuer
kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
    - http01:
        ingress:
          class: nginx
