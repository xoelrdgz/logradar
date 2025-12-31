# syntax=docker/dockerfile:1.4

FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

COPY go.mod go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify
COPY . .

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w \
    -X main.Version=${VERSION} \
    -X main.Commit=${COMMIT} \
    -X main.BuildTime=${BUILD_TIME}" \
    -o logradar \
    ./cmd/logradar

RUN ./logradar version

FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
ARG COMMIT=unknown

LABEL org.opencontainers.image.title="LogRadar" \
    org.opencontainers.image.description="Production-grade HTTP log threat detection system" \
    org.opencontainers.image.version="${VERSION}" \
    org.opencontainers.image.revision="${COMMIT}" \
    org.opencontainers.image.vendor="LogRadar" \
    org.opencontainers.image.source="https://github.com/xoelrdgz/logradar" \
    org.opencontainers.image.licenses="MIT"

COPY --from=builder /build/logradar /logradar
COPY --from=builder /build/configs/config.yaml /etc/logradar/config.yaml
COPY --from=builder /build/configs/config.production.yaml /etc/logradar/config.production.yaml
COPY --from=builder /build/testdata/malicious_ips.txt /etc/logradar/malicious_ips.txt
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

VOLUME ["/var/log/logradar", "/logs"]

USER nonroot:nonroot

EXPOSE 9090

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/logradar", "version"]

ENTRYPOINT ["/logradar"]
CMD ["analyze", "--demo", "--demo-rate", "50000", "--no-tui"]
