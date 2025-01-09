include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/release

include ../lib.Makefile

# The name of the product.
# Either "Calico" or "Calico Enterprise"
PRODUCT_NAME=Calico

export ORGANIZATION
export GIT_REPO
export GIT_REPO_SLUG
export DEV_REGISTRIES
export OPERATOR_BRANCH

LDFLAGS= -X $(PACKAGE_NAME)/pkg/buildinfo.ProductName='$(PRODUCT_NAME)'

.PHONY: build
build: bin/release

clean:
	@rm -rf ./bin
	@rm -rf ./output ./_output ./tmp ./*.log

bin/release: $(shell find . -name "*.go")
	@mkdir -p bin && \
	$(call build_binary, ./cmd, bin/release)

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: static-checks

###############################################################################
# Hashrelease
###############################################################################
.PHONY: hashrelease hashrelease-build hashrelease-publish
hashrelease: hashrelease-build hashrelease-publish

hashrelease-build: bin/release var-require-all-GITHUB_TOKEN
	@bin/release hashrelease build

hashrelease-publish: bin/release var-require-all-GITHUB_TOKEN
	@bin/release hashrelease publish

###############################################################################
# Release
###############################################################################
.PHONY: release-notes
release-notes: bin/release var-require-all-GITHUB_TOKEN
	@bin/release release generate-release-notes
