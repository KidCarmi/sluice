FROM golang:1.25.9 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Release builds override this via --build-arg VERSION=<tag-without-v>.
# Local dev builds fall back to the value baked into cmd/sluice/main.go.
ARG VERSION=dev
# Strip debug info to shave ~30% off the binary (build reproducibility is
# handled separately by the publish workflow).
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /sluice ./cmd/sluice

# Pre-create /data with nonroot ownership so volumes mounted at /data are
# writable by UID 65532 without extra init containers. Distroless has no
# shell, so we stage the directory in a scratch builder stage and COPY it.
FROM alpine:3 AS datadir
RUN mkdir -p /data && chown 65532:65532 /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder --chown=65532:65532 /sluice /sluice
COPY --from=datadir --chown=65532:65532 /data /data
EXPOSE 8443 8080 9090
ENTRYPOINT ["/sluice"]
