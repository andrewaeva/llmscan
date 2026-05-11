# syntax=docker/dockerfile:1.7

# ---------- Stage 1: builder ----------
FROM golang:1.25-alpine AS builder

ARG VERSION=dev
ARG TARGETOS=linux
ARG TARGETARCH=amd64

WORKDIR /src

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

# Bring in the rest of the sources.
COPY . .

ENV CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}

RUN go build \
        -trimpath \
        -ldflags "-s -w -X main.Version=${VERSION}" \
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
