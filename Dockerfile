# CloudGuard-Anomaly Dockerfile
# Multi-stage build for optimized production image

FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    postgresql-client \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.11-slim

LABEL maintainer="CloudGuard Security <security@cloudguard.dev>"
LABEL version="3.0.0"
LABEL description="CloudGuard-Anomaly - Cloud Security Posture Management and Anomaly Detection"

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy Python packages from builder
COPY --from=builder /root/.local /root/.local

# Make sure scripts in .local are usable
ENV PATH=/root/.local/bin:$PATH

# Copy application code
COPY cloudguard_anomaly/ ./cloudguard_anomaly/
COPY alembic/ ./alembic/
COPY alembic.ini ./alembic.ini
COPY .env.example ./.env

# Create non-root user for security
RUN useradd -m -u 1000 cloudguard && \
    chown -R cloudguard:cloudguard /app

# Switch to non-root user
USER cloudguard

# Expose dashboard port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

# Default environment variables
ENV PYTHONUNBUFFERED=1 \
    DASHBOARD_HOST=0.0.0.0 \
    DASHBOARD_PORT=5000

# Entry point script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]

# Default command - run dashboard
CMD ["dashboard"]
