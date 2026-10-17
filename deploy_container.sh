#!/usr/bin/env bash
# ==============================================================================
# LogMind: Container Build & Deploy for IBM LinuxONE (s390x)
# Supports podman (native on RHEL s390x) and docker
# ==============================================================================

set -e

CONTAINER_TOOL="docker"
if command -v podman &> /dev/null; then
    CONTAINER_TOOL="podman"
fi

IMAGE_NAME="logmind:latest"
CONTAINER_NAME="logmind-enclave"

echo "[*] Using container engine: ${CONTAINER_TOOL}"
echo "[*] Building container image for s390x (${IMAGE_NAME})..."

${CONTAINER_TOOL} build -f deployment/Dockerfile -t ${IMAGE_NAME} .

# Stop existing container if running
${CONTAINER_TOOL} rm -f ${CONTAINER_NAME} 2>/dev/null || true

echo "[*] Starting LogMind container on port 8000..."
${CONTAINER_TOOL} run -d \
    --name ${CONTAINER_NAME} \
    -p 8000:8000 \
    --security-opt no-new-privileges:true \
    --restart unless-stopped \
    ${IMAGE_NAME}

echo "=================================================================="
echo " [✓] Container ${CONTAINER_NAME} is running!"
echo " Logs:    ${CONTAINER_TOOL} logs -f ${CONTAINER_NAME}"
echo " Stop:    ${CONTAINER_TOOL} stop ${CONTAINER_NAME}"
echo " Access:  http://localhost:8000"
echo "=================================================================="
