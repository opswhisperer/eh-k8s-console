#!/usr/bin/env bash
# Build and push the image.  ./build.sh [tag]   (default: git describe)
# Env: IMAGE (default ghcr.io/opswhisperer/eh-k8s-console), PLATFORMS (default linux/amd64).
set -euo pipefail
cd "$(dirname "$0")"
TAG=${1:-$(git describe --tags --always --dirty)}
IMAGE=${IMAGE:-ghcr.io/opswhisperer/eh-k8s-console}
go test ./...
docker buildx build --platform "${PLATFORMS:-linux/amd64}" --build-arg VERSION="$TAG" \
  -t "$IMAGE:$TAG" -t "$IMAGE:latest" --push .
echo "pushed $IMAGE:$TAG"
