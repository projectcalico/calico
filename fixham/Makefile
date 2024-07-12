include ../metadata.mk

NAME = fixham
PACKAGE_NAME = github.com/projectcalico/calico/fixham

include ../lib.Makefile

.PHONY: build
build: bin/hashrelease bin/release

clean:
	@rm -rf ./bin

bin/release:
	@mkdir -p bin
	@go build -o bin/release ./release

bin/hashrelease:
	@mkdir -p bin
	@go build -o bin/hashrelease ./hashrelease
