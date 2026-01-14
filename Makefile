.PHONY: vendor
vendor: vendor/modules.txt

vendor/modules.txt: go.mod
	go mod vendor

.PHONY: build
build: cvetool

VERSION ?= $(shell git describe --tags --match 'v*' --always --dirty 2>/dev/null || echo dev)
cvetool: vendor
	go build -ldflags "-X main.Version=${VERSION}" ./cmd/...
