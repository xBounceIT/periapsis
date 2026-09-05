FROM --platform=$BUILDPLATFORM golang:1.26.7-alpine3.23@sha256:b17af760035fc2f338eed92d448a6c67f2d45438844fc6c60678fa5f99e44b57 AS build

ARG TARGETARCH
ARG TARGETOS

WORKDIR /workspace/services/api

COPY modules/customfields/ /workspace/modules/customfields/
COPY modules/contacts/ /workspace/modules/contacts/
COPY modules/dfir/ /workspace/modules/dfir/
COPY modules/identity/ /workspace/modules/identity/
COPY modules/sla/ /workspace/modules/sla/
COPY modules/ticketing/ /workspace/modules/ticketing/
COPY services/api/go.mod services/api/go.sum ./
RUN go mod download

COPY services/api/ ./
COPY deploy/compose/healthcheck.go /tmp/healthcheck.go

RUN mkdir -p /out/tmp \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
      go build -buildvcs=false -trimpath -ldflags="-s -w -buildid=" \
      -o /out/periapsis-api ./cmd/api \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
      go build -buildvcs=false -trimpath -ldflags="-s -w -buildid=" \
      -o /out/healthcheck /tmp/healthcheck.go \
    && chmod 1770 /out/tmp

FROM scratch

ARG REVISION=unknown
ARG VERSION=development

LABEL org.opencontainers.image.description="Periapsis versioned HTTP API" \
      org.opencontainers.image.licenses="UNLICENSED" \
      org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.source="https://github.com/periapsis-im/periapsis" \
      org.opencontainers.image.title="Periapsis API" \
      org.opencontainers.image.version=$VERSION

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=10001:10001 /out/periapsis-api /periapsis-api
COPY --from=build --chown=10001:10001 /out/healthcheck /healthcheck
COPY --from=build --chown=10001:10001 /out/tmp /tmp

ENV HOME=/tmp \
    PERIAPSIS_API_ADDR=0.0.0.0:8080 \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    TMPDIR=/tmp

USER 10001:10001
EXPOSE 8080
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/healthcheck", "http://127.0.0.1:8080/health/live"]

ENTRYPOINT ["/periapsis-api"]
