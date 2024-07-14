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

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: static-checks

###############################################################################
# Hashrelease
###############################################################################
hashrelease: bin/hashrelease
	@NAME=calico \
	GO_BUILD_VER=$(GO_BUILD_VER) \
	REPO_ROOT=$(REPO_ROOT) \
	bin/hashrelease publish
