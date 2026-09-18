.PHONY: build test

build:
	mkdir -p bin
	cd engine/restic && CGO_ENABLED=0 go build -o ../../bin/restic ./cmd/restic
	CGO_ENABLED=0 go build -o bin/wormhole ./cmd/wormhole

test:
	go test ./...
	cd engine/restic && go test ./internal/filter ./cmd/restic -run 'TestIncludeByPath|TestMetadataEqualPortable'
