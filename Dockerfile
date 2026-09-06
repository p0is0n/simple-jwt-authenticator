FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build

WORKDIR /src

ARG TARGETOS
ARG TARGETARCH

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

COPY go.mod go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
    -mod=readonly \
    -trimpath \
    -ldflags="-s -w \
        -X simple-jwt-authenticator/internal/buildinfo.version=${VERSION} \
        -X simple-jwt-authenticator/internal/buildinfo.commit=${COMMIT} \
        -X simple-jwt-authenticator/internal/buildinfo.date=${BUILD_DATE}" \
    -o /out/server \
    ./cmd/server \
    && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
    -mod=readonly \
    -trimpath \
    -ldflags="-s -w \
        -X simple-jwt-authenticator/internal/buildinfo.version=${VERSION} \
        -X simple-jwt-authenticator/internal/buildinfo.commit=${COMMIT} \
        -X simple-jwt-authenticator/internal/buildinfo.date=${BUILD_DATE}" \
    -o /out/cli \
    ./cmd/cli


FROM alpine:3.24 AS runtime

RUN apk add --no-cache ca-certificates \
    && addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -G app app

WORKDIR /app

USER app


FROM runtime AS cli

COPY --from=build --chown=app:app /out/cli /app/cli

ENTRYPOINT ["/app/cli"]


FROM runtime AS server

COPY --from=build --chown=app:app /out/server /app/server

EXPOSE 8080

HEALTHCHECK \
    --interval=30s \
    --timeout=3s \
    --start-period=5s \
    --retries=3 \
    CMD response="$(wget -qO- http://127.0.0.1:8080/healthz 2>&1)" \
        && { \
            if [ "$response" = "ok" ]; then \
                echo "OK"; \
            else \
                echo "unexpected response: $response"; \
                exit 1; \
            fi; \
        } \
        || { \
            echo "request failed: $response"; \
            exit 1; \
        }

ENTRYPOINT ["/app/server"]
