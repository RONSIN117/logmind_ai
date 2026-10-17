# Multi-architecture Dockerfile for IBM LinuxONE (s390x) & x86_64
# Base image: Red Hat Universal Base Image (UBI 9) for s390x
FROM --platform=$TARGETPLATFORM registry.access.redhat.com/ubi9/python-311:latest

USER 0
WORKDIR /app

# Install system dependencies
RUN dnf install -y --nodocs findutils gcc curl && dnf clean all

# Copy requirements & install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source & datasets
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY data/ ./data/

# Run as non-root user for enterprise container security compliance
USER 1001

EXPOSE 8000

# Health check for OpenShift / Kubernetes
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/api/status || exit 1

CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
