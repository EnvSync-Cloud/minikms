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

echo "==> Waiting for minikms on port 50051..."
for i in $(seq 1 30); do
  if nc -z localhost 50051 2>/dev/null; then
    echo "    minikms is ready"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "    ERROR: minikms did not become ready in time"
    docker compose -f "$COMPOSE_FILE" logs minikms
    exit 1
  fi
  sleep 1
done

echo "==> Waiting for Vault on port 8200..."
for i in $(seq 1 30); do
  if nc -z localhost 8200 2>/dev/null; then
    echo "    Vault is ready"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "    ERROR: Vault did not become ready in time"
    docker compose -f "$COMPOSE_FILE" logs vault
    exit 1
  fi
  sleep 1
done

echo "==> Running gRPC client example..."
go run ./examples/vault-docker/

echo "==> Docker E2E test passed!"
