FROM golang:1.25 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /sluice ./cmd/sluice

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /sluice /sluice
EXPOSE 8443 8080 9090
ENTRYPOINT ["/sluice"]
