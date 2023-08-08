FROM golang:alpine as builder

RUN apk add --no-cache make git
WORKDIR /easy-get-proxy
COPY . /easy-get-proxy
RUN go mod download && \
    go mod tidy && \
    make docker && \
    mv ./bin/proxypool-docker /proxypool

FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata
ENV TZ Asia/Shanghai
WORKDIR /easy-get-proxy
COPY ./assets /proxypool-src/assets
COPY ./config /proxypool-src/config
COPY --from=builder /proxypool /proxypool-src/
ENTRYPOINT ["/proxypool-src/proxypool"]
