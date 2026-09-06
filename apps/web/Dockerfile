# Client assets and the Node-only server are architecture-independent outputs.
FROM --platform=$BUILDPLATFORM node:24.20.0-alpine3.23@sha256:0388af2af070cd4736a1567cfed02469ba117848845b4165d87a333edb53d2ca AS build

# This immutable Node base still contains OpenSSL 3.5.7 on both architectures.
RUN apk add --no-cache --upgrade libcrypto3=3.5.8-r0 libssl3=3.5.8-r0

ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
WORKDIR /workspace

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/web/package.json apps/web/package.json
COPY packages/config/package.json packages/config/package.json
COPY packages/contracts/package.json packages/contracts/package.json
COPY packages/db/package.json packages/db/package.json
COPY packages/tsconfig/package.json packages/tsconfig/package.json
COPY packages/ui/package.json packages/ui/package.json

RUN corepack pnpm install --frozen-lockfile --filter @periapsis/web...

COPY apps/web/ apps/web/
COPY packages/contracts/ packages/contracts/
COPY packages/tsconfig/ packages/tsconfig/
COPY packages/ui/ packages/ui/

RUN corepack pnpm --filter @periapsis/contracts build \
    && corepack pnpm --filter @periapsis/web build

FROM node:24.20.0-alpine3.23@sha256:0388af2af070cd4736a1567cfed02469ba117848845b4165d87a333edb53d2ca

ARG REVISION=unknown
ARG VERSION=development

LABEL org.opencontainers.image.description="Periapsis static web and same-origin API proxy" \
      org.opencontainers.image.licenses="UNLICENSED" \
      org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.source="https://github.com/periapsis-im/periapsis" \
      org.opencontainers.image.title="Periapsis Web" \
      org.opencontainers.image.version=$VERSION

RUN apk add --no-cache --upgrade libcrypto3=3.5.8-r0 libssl3=3.5.8-r0 \
    && addgroup -S -g 10001 periapsis \
    && adduser -S -D -H -u 10001 -G periapsis periapsis \
    && install -d -o 10001 -g 10001 -m 1770 /app /tmp

WORKDIR /app

COPY --from=build --chown=10001:10001 /workspace/apps/web/dist ./dist
COPY --from=build --chown=10001:10001 /workspace/apps/web/dist-server ./dist-server

RUN rm -rf /usr/local/lib/node_modules/corepack /usr/local/lib/node_modules/npm \
      /etc/apk /var/cache/apk \
    && rm -f /usr/local/bin/corepack /usr/local/bin/npm /usr/local/bin/npx \
      /usr/local/bin/pnpm /usr/local/bin/pnpx /usr/local/bin/yarn /usr/local/bin/yarnpkg \
      /sbin/apk /usr/bin/apk

ENV HOME=/tmp \
    NODE_ENV=production \
    PERIAPSIS_WEB_ADDR=0.0.0.0:8081 \
    TMPDIR=/tmp

USER 10001:10001
EXPOSE 8081
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8081/health/live',{signal:AbortSignal.timeout(2000)}).then(response=>{if(!response.ok)process.exit(1)}).catch(()=>process.exit(1))"]

ENTRYPOINT ["node", "dist-server/index.js"]
