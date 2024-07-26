include ../metadata.mk

NAME = fixham
PACKAGE_NAME = github.com/projectcalico/calico/fixham

include ../lib.Makefile

.PHONY: build
build: bin/hashrelease bin/release

clean:
	@rm -rf ./bin
	@rm -rf ./output ./tmp

bin/release: $(shell find . -name "*.go")
	@mkdir -p bin && \
	$(call build_binary, ./release, bin/release)

bin/hashrelease: $(shell find . -name "*.go")
	@mkdir -p bin && \
	$(call build_binary, ./hashrelease, bin/hashrelease)

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

###############################################################################
# Release
###############################################################################
.PHONY: release-notes
release-notes: bin/release var-require-all-GITHUB_TOKEN
	@ORGANIZATION=$(ORGANIZATION) \
	REPO_ROOT=$(REPO_ROOT) \
	bin/release release-notes