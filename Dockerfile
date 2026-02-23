# Build Stage
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o reason-proxy main.go

# Runtime Stage
FROM alpine:latest
WORKDIR /app
RUN apk add --no-cache ca-certificates

# Copy binary
COPY --from=builder /app/reason-proxy .

# Persistence for DB and CA keys
VOLUME /data

# Expose proxy port
EXPOSE 8080

# Run with data stored in volume
ENTRYPOINT ["./reason-proxy", "-port", "8080", "-db", "/data/audit.db", "-ca-cert", "/data/ca.pem", "-ca-key", "/data/ca.key"]
