.PHONY: vendor
vendor: vendor/modules.txt

vendor/modules.txt: go.mod
	go mod vendor

.PHONY: build
build: cvetool

cvetool: vendor
	go build ./cmd/...
