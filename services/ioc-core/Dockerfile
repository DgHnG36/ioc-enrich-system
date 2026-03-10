FROM golang:1.24.2-alpine AS builder

RUN apk add --no-cache git tzdata

WORKDIR /app
COPY shared/go/ ./shared/go
COPY services/ioc-core/go.mod services/ioc-core/go.sum ./services/ioc-core/

COPY services/ioc-core ./services/ioc-core

WORKDIR /app/services/ioc-core

# This command will be replace when project push to github
RUN go mod edit -replace github.com/DgHnG36/ioc-enrich-system/shared/go=../../shared/go
RUN go mod download
RUN go mod tidy

WORKDIR /app/services/ioc-core
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /app/bin/ioc-core cmd/server/main.go

FROM alpine:3.23

RUN apk add --no-cache ca-certificates tzdata
ENV TZ=Asia/Ho_Chi_Minh

WORKDIR /app

COPY --from=builder /app/bin/ioc-core .
RUN chmod +x /app/ioc-core

EXPOSE 50051

CMD ["./ioc-core"]
