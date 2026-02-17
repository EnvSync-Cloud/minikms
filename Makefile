.PHONY: build run test proto clean docker migrate

BINARY_NAME=minikms
GO=go

build:
	$(GO) build -o bin/$(BINARY_NAME) ./cmd/minikms

run: build
	./bin/$(BINARY_NAME)

test:
	$(GO) test ./... -v -race

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
