FROM golang:1.24.2-alpine AS builder

RUN apk add --no-cache git tzdata

WORKDIR /app
COPY shared/go ./shared/go
COPY services/ioc-api-gateway/go.mod services/ioc-api-gateway/go.sum ./services/ioc-api-gateway/

WORKDIR /app/services/ioc-api-gateway
COPY services/ioc-api-gateway /app/services/ioc-api-gateway/

WORKDIR /app/services/ioc-api-gateway

# This command above will be replace after git push to github
RUN go mod edit -replace github.com/DgHnG36/ioc-enrich-system/shared/go=../../shared/go

RUN go mod download
RUN go mod tidy

WORKDIR /app/services/ioc-api-gateway
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /app/bin/ioc-api-gateway cmd/server/main.go

FROM alpine:3.23
RUN apk add --no-cache ca-certificates tzdata curl
ENV TZ=Asia/Ho_Chi_Minh

WORKDIR /app
COPY --from=builder /app/bin/ioc-api-gateway .
RUN chmod +x /app/ioc-api-gateway

# Health check to ensure service is running and responsive
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080
CMD ["./ioc-api-gateway"]

