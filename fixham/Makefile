include ../metadata.mk

NAME = fixham
PACKAGE_NAME = github.com/projectcalico/calico/fixham

include ../lib.Makefile

.PHONY: build
build: bin/hashrelease bin/release

clean:
	@rm -rf ./bin
	@rm -rf ./output

bin/release: $(shell find . -name "*.go")
	@mkdir -p bin
	@go build -o bin/release ./release

bin/hashrelease: $(shell find . -name "*.go")
	@mkdir -p bin
	@go build -o bin/hashrelease ./hashrelease

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: static-checks

###############################################################################
# Hashrelease
###############################################################################
hashrelease: bin/hashrelease
	@ORGANIZATION=$(ORGANIZATION) \
	REPO_ROOT=$(REPO_ROOT) \
	bin/hashrelease publish
