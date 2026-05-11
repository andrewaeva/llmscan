# llmscan — developer Makefile
# Common targets for local development and CI.

BINARY      := llmscan
PKG         := github.com/andrewaeva/llmscan
TESTED_PKGS := $(shell go list ./... | grep -v /examples/)
COVER_FILE  := coverage.out

.PHONY: help build install test test-race test-cover test-cover-html bench bench-cpu bench-mem fmt vet tidy clean

help:
	@echo "Targets:"
	@echo "  build           - build the llmscan binary"
	@echo "  install         - install to GOBIN/GOPATH/bin"
	@echo "  test            - run unit tests (only tested packages, avoids covdata issue)"
	@echo "  test-race       - run tests with race detector"
	@echo "  test-cover      - run tests with coverage profile"
	@echo "  test-cover-html - open coverage report in browser"
	@echo "  bench           - run all benchmarks (1x)"
	@echo "  bench-cpu       - run benchmarks with CPU profile"
	@echo "  bench-mem       - run benchmarks with allocation reports"
	@echo "  fmt             - gofmt -s -w"
	@echo "  vet             - go vet"
	@echo "  tidy            - go mod tidy"
	@echo "  clean           - remove build artifacts and coverage files"

build:
	go build -o $(BINARY) ./cmd/llmscan

install:
	go install ./cmd/llmscan

test:
	go test -count=1 ./...

test-race:
	go test -count=1 -race ./...

test-cover:
	go test -count=1 -coverprofile=$(COVER_FILE) -covermode=atomic $(TESTED_PKGS)
	@go tool cover -func=$(COVER_FILE) | tail -n 1

test-cover-html: test-cover
	go tool cover -html=$(COVER_FILE)

bench:
	go test -run=^$$ -bench=. -benchtime=2x ./...

bench-cpu:
	go test -run=^$$ -bench=. -benchtime=3s -cpuprofile=cpu.prof ./internal/...

bench-mem:
	go test -run=^$$ -bench=. -benchmem -benchtime=2x ./...

fmt:
	gofmt -s -w .

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -f $(BINARY) $(COVER_FILE) cpu.prof mem.prof
