include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/release

include ../lib.Makefile

export ORGANIZATION
export GIT_REPO
export GIT_REPO_SLUG
export DEV_REGISTRIES
export OPERATOR_BRANCH

.PHONY: build
build: bin/release

clean:
	@rm -rf ./bin
	@rm -rf ./output ./_output ./report ./tmp ./*.log

bin/release: $(shell find . -name "*.go")
	@mkdir -p bin && \
	$(call build_binary, ./cmd, bin/release)

POSTRELEASE_TEST_PACKAGE		:= $(PACKAGE_NAME)/pkg/postrelease
UNIT_TEST_PACKAGES	:= $(shell go list ./... | grep -v $(POSTRELEASE_TEST_PACKAGE))
ut: bin/gotestsum
	@mkdir -p report
	@$(DOCKER_GO_BUILD) gotestsum --junitfile report/unit-tests.xml \
		-- -coverprofile=report/coverage.out $(UNIT_TEST_PACKAGES)

GOTESTSUM_VERSION := v1.12.1
bin/gotestsum:
	@mkdir -p bin
	@$(DOCKER_GO_BUILD) go install gotest.tools/gotestsum@$(GOTESTSUM_VERSION)

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: static-checks ut

###############################################################################
# Hashrelease
###############################################################################
.PHONY: hashrelease hashrelease-build hashrelease-publish
hashrelease: hashrelease-build hashrelease-publish

hashrelease-build: bin/release var-require-all-GITHUB_TOKEN
	@bin/release hashrelease build

hashrelease-publish: bin/release var-require-all-GITHUB_TOKEN
	@bin/release hashrelease publish

hashrelease-svr-gc: bin/release
	@bin/release hashrelease garbage-collect

###############################################################################
# Release
###############################################################################
.PHONY: release-notes
release-notes: bin/release var-require-all-GITHUB_TOKEN
	@bin/release release generate-release-notes
