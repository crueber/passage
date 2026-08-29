.PHONY: css build test vet

css:
	./tools/build-css.sh

build:
	CGO_ENABLED=0 go build ./...

test:
	go test -race ./...

vet:
	go vet ./...
