include ../metadata.mk

NAME = fixham
PACKAGE_NAME = github.com/projectcalico/fixham

.PHONY: bin/fixham
bin/fixham:
	mkdir -p bin
	go build -o bin/fixham ./build

.PHONY: help
help: bin/fixham
	@bin/fixham --help

.PHONY: clean
clean: bin/fixham
	@bin/fixham clean


