SHELL := /usr/bin/env bash
.PHONY: tools proto web-build build test test-race lint clean

BIN_DIR := $(CURDIR)/bin
TOOL_BIN := $(CURDIR)/.bin
export PATH := $(TOOL_BIN):$(PATH)

tools:
	@mkdir -p $(TOOL_BIN)
	GOBIN=$(TOOL_BIN) go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	GOBIN=$(TOOL_BIN) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

proto:
	@mkdir -p $(TOOL_BIN)
	@test -x $(TOOL_BIN)/protoc-gen-go || $(MAKE) tools
	go tool buf generate

web-build:
	@if [ -f web/package.json ]; then pnpm --dir web install --frozen-lockfile && pnpm --dir web build; fi

build: web-build
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -o $(BIN_DIR)/hive ./cmd/hive
	CGO_ENABLED=0 go build -o $(BIN_DIR)/sensor-agent ./cmd/sensor-agent
	CGO_ENABLED=0 go build -o $(BIN_DIR)/docker-guard-proxy ./cmd/docker-guard-proxy
	CGO_ENABLED=0 go build -o $(BIN_DIR)/nginx-guard ./cmd/nginx-guard

test:
	CGO_ENABLED=0 go test ./...

test-race:
	go test -race ./...

lint:
	go vet ./...

clean:
	rm -rf $(BIN_DIR) $(TOOL_BIN)
