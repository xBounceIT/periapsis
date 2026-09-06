ARG NODE_IMAGE=node:24.19.0-alpine3.23@sha256:244cc2b53f46f9e876304391d17682b0ddae9ac33491f4857e25e35a36ba7995
ARG POSTGRES_IMAGE=postgres:18.6-alpine3.23@sha256:697c180dbf244d3ce4a8f4cbc0156cde840af055c1bf8b76aebe422a4822086f
ARG GO_IMAGE=golang:1.26.7-alpine3.23@sha256:b17af760035fc2f338eed92d448a6c67f2d45438844fc6c60678fa5f99e44b57

FROM ${NODE_IMAGE} AS node-runtime

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS sla-worker-build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /workspace/services/worker
COPY modules/ /workspace/modules/
COPY services/worker/go.mod services/worker/go.sum ./
RUN go mod download
COPY services/worker/ ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -buildvcs=false -trimpath -ldflags="-s -w -buildid=" \
    -o /out/performance-sla ./cmd/performance-sla

FROM ${POSTGRES_IMAGE}

ARG REVISION=unknown

LABEL org.opencontainers.image.description="Disposable PostgreSQL 18.6 ticketing performance gate" \
      org.opencontainers.image.licenses="UNLICENSED" \
      org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.source="https://github.com/periapsis-im/periapsis" \
      org.opencontainers.image.title="Periapsis Performance Gate"

COPY --from=node-runtime /usr/local/ /usr/local/
COPY --from=sla-worker-build /out/performance-sla /usr/local/bin/performance-sla

ENV CI=true \
    COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    HOME=/tmp \
    TMPDIR=/tmp \
    PERIAPSIS_PERFORMANCE_SLA_WORKER=/usr/local/bin/performance-sla

WORKDIR /workspace

COPY . .

RUN node --version \
    && psql --version \
    && corepack pnpm install --frozen-lockfile \
    && node --test tests/performance/*.test.mjs \
    && chmod 0755 /workspace/scripts/performance/run-ci-ticketing-hot-paths.sh \
    && addgroup -S -g 10001 performance \
    && adduser -S -D -H -h /tmp -u 10001 -G performance performance \
    && mkdir -p /workspace/tmp/performance

USER 10001:10001
STOPSIGNAL SIGTERM

ENTRYPOINT ["/workspace/scripts/performance/run-ci-ticketing-hot-paths.sh"]
