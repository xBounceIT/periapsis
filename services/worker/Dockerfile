FROM --platform=$BUILDPLATFORM golang:1.26.7-alpine3.23@sha256:b17af760035fc2f338eed92d448a6c67f2d45438844fc6c60678fa5f99e44b57 AS build

ARG TARGETARCH
ARG TARGETOS

WORKDIR /workspace/services/worker

COPY modules/ /workspace/modules/
COPY services/worker/go.mod services/worker/go.sum ./
RUN go mod download

COPY services/worker/ ./
COPY deploy/compose/healthcheck.go /tmp/healthcheck.go

RUN mkdir -p /out/tmp \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
      go build -buildvcs=false -trimpath -ldflags="-s -w -buildid=" \
      -o /out/periapsis-worker ./cmd/worker \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
      go build -buildvcs=false -trimpath -ldflags="-s -w -buildid=" \
      -o /out/healthcheck /tmp/healthcheck.go \
    && chmod 1770 /out/tmp

FROM scratch

ARG REVISION=unknown
ARG VERSION=development

LABEL org.opencontainers.image.description="Periapsis durable background worker" \
      org.opencontainers.image.licenses="UNLICENSED" \
      org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.source="https://github.com/periapsis-im/periapsis" \
      org.opencontainers.image.title="Periapsis Worker" \
      org.opencontainers.image.version=$VERSION

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=10001:10001 /out/periapsis-worker /periapsis-worker
COPY --from=build --chown=10001:10001 /out/healthcheck /healthcheck
COPY --from=build --chown=10001:10001 /out/tmp /tmp

ENV HOME=/tmp \
    PERIAPSIS_WORKER_ADDR=0.0.0.0:8082 \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    TMPDIR=/tmp

USER 10001:10001
EXPOSE 8082
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/healthcheck", "http://127.0.0.1:8082/health/live"]

ENTRYPOINT ["/periapsis-worker"]
