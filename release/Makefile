include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/release

include ../lib.Makefile

.PHONY: build
build: bin/release

clean:
	@rm -rf ./bin
	@rm -rf ./output ./tmp

bin/release: $(shell find . -name "*.go")
	@mkdir -p bin && \
	$(call build_binary, ./build, bin/release)

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: static-checks

###############################################################################
# Hashrelease
###############################################################################
hashrelease: bin/release
	@ORGANIZATION=$(ORGANIZATION) \
	REPO_ROOT=$(REPO_ROOT) \
	IS_HASHRELEASE=true \
	bin/release publish

###############################################################################
# Release
###############################################################################
.PHONY: release-notes
release-notes: bin/release var-require-all-GITHUB_TOKEN
	@ORGANIZATION=$(ORGANIZATION) \
	REPO_ROOT=$(REPO_ROOT) \
	IS_HASHRELEASE=false \
	bin/release release-notes
