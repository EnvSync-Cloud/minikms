.PHONY: build run test test-unit test-e2e cover cover-html proto clean docker migrate lint fmt

BINARY_NAME=minikms
GO=go

build:
	$(GO) build -o bin/$(BINARY_NAME) ./cmd/minikms

run: build
	./bin/$(BINARY_NAME)

test:
	$(GO) test ./... -v -race

test-unit:
	$(GO) test ./internal/... -v -race -count=1

test-e2e:
	./scripts/e2e-test.sh

cover:
	$(GO) test ./internal/... -race -coverprofile=coverage.out -covermode=atomic
	$(GO) tool cover -func=coverage.out

cover-html: cover
	$(GO) tool cover -html=coverage.out -o coverage.html

proto:
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		api/proto/minikms/v1/*.proto

clean:
	rm -rf bin/

docker:
	docker build -t minikms:latest .

migrate:
	@echo "Run: psql \$$MINIKMS_DB_URL -f migrations/001_initial_schema.sql"

lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w .
