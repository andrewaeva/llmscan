# syntax=docker/dockerfile:1.7

# ---------- Stage 1: builder ----------
FROM golang:1.25-alpine AS builder

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src

# tree-sitter grammars are cgo, so CGO is required. gcc + musl-dev provide the
# toolchain; static linking against musl keeps the runtime image dependency-free.
RUN apk add --no-cache gcc musl-dev

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

# Bring in the rest of the sources.
COPY . .

ENV CGO_ENABLED=1 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}

RUN go build \
        -trimpath \
        -ldflags "-s -w -X main.Version=${VERSION} -linkmode external -extldflags '-static'" \
        -o /out/llmscan \
        ./cmd/llmscan

# ---------- Stage 2: runtime ----------
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/andrewaeva/llmscan" \
      org.opencontainers.image.description="LLM-based multi-agent code security scanner" \
      org.opencontainers.image.licenses="MIT"

COPY --from=builder /out/llmscan /llmscan
COPY --from=builder /src/skills /skills

USER nonroot:nonroot
WORKDIR /work

ENTRYPOINT ["/llmscan"]
