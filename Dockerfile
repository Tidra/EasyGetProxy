FROM golang:alpine AS builder

WORKDIR /build
RUN adduser -u 10001 -D app-runner

ENV GOPROXY https://goproxy.cn
COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -a -o easy-get-proxy .

FROM alpine:latest AS final

RUN apk add --no-cache ca-certificates tzdata
ENV TZ Asia/Shanghai
WORKDIR /app
COPY --from=builder /build/easy-get-proxy /app/
COPY --from=builder /build/assets /app/assets
COPY --from=builder /build/config /app/config
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

USER app-runner
ENTRYPOINT ["/app/easy-get-proxy"]
