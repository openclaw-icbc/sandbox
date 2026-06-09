#!/usr/bin/env bash
set -euo pipefail

IMAGE_NAME="openclaw-sandbox:bookworm"

DOCKER_BUILDKIT=1 docker build -t "${IMAGE_NAME}" -f Dockerfile.sandbox-full .
echo "Built ${IMAGE_NAME}"
