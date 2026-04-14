# Sluice CDR Engine — development Makefile
#
# Requires: protoc (apt install protobuf-compiler) and Go protoc plugins.
# Run `make tools` to install the Go plugins into $(go env GOPATH)/bin.

GOBIN := $(shell go env GOPATH)/bin

.PHONY: help
help:
	@echo "Targets:"
	@echo "  proto     Regenerate *.pb.go files from the .proto source"
	@echo "  tools     Install protoc-gen-go + protoc-gen-go-grpc"
	@echo "  build     Build the sluice binary"
	@echo "  test      Run tests with race detector"
	@echo "  bench     Run benchmarks"
	@echo "  lint      Run golangci-lint"
	@echo "  gosec     Run gosec"
	@echo "  clean     Remove built binary"

.PHONY: tools
tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

.PHONY: proto
proto:
	PATH="$(GOBIN):$$PATH" protoc \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/sluicev1/sluice.proto

.PHONY: build
build:
	CGO_ENABLED=0 go build -o sluice ./cmd/sluice

.PHONY: test
test:
	go test -race -count=1 ./...

.PHONY: bench
bench:
	go test -bench=. -benchmem -run=^$$ ./internal/sanitizer/

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: gosec
gosec:
	gosec ./...

.PHONY: clean
clean:
	rm -f sluice
