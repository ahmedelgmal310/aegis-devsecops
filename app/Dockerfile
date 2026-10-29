# syntax=docker/dockerfile:1

# Base images are pinned by digest; Dependabot keeps the pins fresh.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG COMMIT=unknown
# One Dockerfile, one binary per image: ledger (the workload) or responder
# (the incident responder). Neither image contains the other's code.
ARG COMPONENT=ledger
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/app ./cmd/${COMPONENT}

# Distroless static: no shell, no package manager, runs as UID 65532.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:18f4cc26c9ffa7f20a359298be7deadac5c607c8e03a02b8119f1a5fc2f82c99

ARG COMPONENT=ledger
ARG PORTS=8080
LABEL org.opencontainers.image.title="aegis-${COMPONENT}" \
      org.opencontainers.image.description="Aegis DevSecOps platform: ${COMPONENT}" \
      org.opencontainers.image.source="https://github.com/ahmedelgmal310/aegis-devsecops" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/app /app
USER 65532:65532
EXPOSE ${PORTS}
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["/app", "healthcheck"]
ENTRYPOINT ["/app"]
