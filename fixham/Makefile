include ../metadata.mk
include ../lib.Makefile

NAME = fixham
PACKAGE_NAME = github.com/projectcalico/calico/fixham

include ../lib.Makefile

.PHONY: build
build: bin/fixham

clean:
	@rm -rf ./bin

bin/fixham:
	@mkdir -p bin
	@go build -o bin/fixham ./build
