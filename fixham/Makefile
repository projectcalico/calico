include ../metadata.mk

export NAME = fixham
export PACKAGE_NAME = github.com/projectcalico/fixham

.PHONY: default
default: fixham

.PHONY: bin/fixham
bin/fixham:
	@mkdir -p bin
	@go build -o bin/fixham ./build

.PHONY: fixham
fixham: bin/fixham
	@bin/fixham $(ARGS)

.PHONY: %
# Allow to run any target with `make <target>`
%:
	@bin/fixham $@

