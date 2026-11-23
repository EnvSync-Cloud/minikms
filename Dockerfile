FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /minikms ./cmd/minikms \
 && CGO_ENABLED=0 GOOS=linux go build -o /minikms-escrow ./cmd/minikms-escrow \
 && CGO_ENABLED=0 GOOS=linux go build -o /minikms-rewrap ./cmd/minikms-rewrap

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata netcat-openbsd
RUN adduser -D -g '' minikms

COPY --from=builder /minikms /usr/local/bin/minikms
COPY --from=builder /minikms-escrow /usr/local/bin/minikms-escrow
COPY --from=builder /minikms-rewrap /usr/local/bin/minikms-rewrap
COPY migrations/ /migrations/

USER minikms

EXPOSE 50051

ENTRYPOINT ["minikms"]
