FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /minikms ./cmd/minikms

FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata
RUN adduser -D -g '' minikms

COPY --from=builder /minikms /usr/local/bin/minikms
COPY migrations/ /migrations/

USER minikms

EXPOSE 50051

ENTRYPOINT ["minikms"]
