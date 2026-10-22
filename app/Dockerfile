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
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/ledger ./cmd/ledger

# Distroless static: no shell, no package manager, runs as UID 65532.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88

LABEL org.opencontainers.image.title="aegis-ledger" \
      org.opencontainers.image.description="Demo workload for the Aegis DevSecOps platform" \
      org.opencontainers.image.source="https://github.com/ahmedelgmal310/aegis-devsecops" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /out/ledger /ledger
USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["/ledger", "healthcheck"]
ENTRYPOINT ["/ledger"]
