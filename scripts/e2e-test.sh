#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

COMPOSE_FILE="$PROJECT_DIR/docker-compose.test.yaml"

cleanup() {
    echo "Cleaning up test containers..."
    docker compose -f "$COMPOSE_FILE" down -v --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

echo "Starting test databases..."
docker compose -f "$COMPOSE_FILE" up -d --wait

echo "Running migrations..."
export MINIKMS_DB_URL="postgres://minikms_test:testpass@localhost:5433/minikms_test?sslmode=disable"
psql "$MINIKMS_DB_URL" -f "$PROJECT_DIR/migrations/001_initial_schema.sql"

echo "Running E2E tests..."
export MINIKMS_REDIS_URL="redis://localhost:6380/0"
export MINIKMS_ROOT_KEY="$(openssl rand -hex 32)"

cd "$PROJECT_DIR"
go test ./internal/store/... ./internal/service/... -tags=e2e -v -race -count=1

echo "E2E tests passed!"
