#!/usr/bin/env bash
set -euo pipefail

COMPOSE_FILE="docker-compose.test.yaml"

cleanup() {
  echo "Cleaning up..."
  docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

echo "==> Starting services..."
docker compose -f "$COMPOSE_FILE" up -d --build --wait

echo "==> Waiting for both miniKMS replicas..."
for i in $(seq 1 30); do
  if nc -z localhost 50051 2>/dev/null && nc -z localhost 50052 2>/dev/null; then
    echo "    both replicas are ready"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "    ERROR: miniKMS replicas did not become ready in time"
    docker compose -f "$COMPOSE_FILE" logs minikms-1 minikms-2
    exit 1
  fi
  sleep 1
done

echo "==> Running gRPC client example..."
go run ./examples/grpc-e2e/

echo "==> Running two-replica HA gRPC flow..."
go run ./examples/grpc-ha-e2e/

echo "==> Docker E2E test passed!"
