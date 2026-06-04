include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/release

include ../lib.Makefile

.PHONY: build
build: bin/release

clean:
	@rm -rf ./bin ./output ./_output ./report ./tmp
	@rm -f ./internal/defaults/metadata.mk
	@find ../ -name '*release*.log' -delete
	@find . -name '*.received.*' -delete

# Stage metadata.mk next to embed.go so go:embed (which requires paths relative to the source file) can pick it up.
# Embedding also makes the binary self-contained across invocation dirs (root Makefile vs release/).
internal/defaults/metadata.mk: ../metadata.mk
	@cp ../metadata.mk $@

bin/release: $(shell find . -name "*.go" -or -name "*.gotmpl") internal/defaults/metadata.mk
	@mkdir -p bin
	@$(DOCKER_RUN) \
		-e CGO_ENABLED=0 \
		$(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) go build -o bin/release -v -buildvcs=false -tags with_embed -ldflags "$(LDFLAGS)" ./cmd'

POSTRELEASE_TEST_PACKAGE		:= $(PACKAGE_NAME)/pkg/postrelease
UNIT_TEST_PACKAGES	:= $(shell go list ./... | grep -v $(POSTRELEASE_TEST_PACKAGE))
ut:
	@mkdir -p report
	@$(DOCKER_GO_BUILD) gotestsum --junitfile report/unit-tests.xml \
		-- -coverprofile=report/coverage.out $(UNIT_TEST_PACKAGES)

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

# Ensures helm is in the bin dir relative to repo root
../bin/helm:
	@$(MAKE) -C ../ helm

hashrelease-build: bin/release var-require-all-GITHUB_TOKEN
	@bin/release hashrelease build

hashrelease-publish: bin/release var-require-all-GITHUB_TOKEN ../bin/helm
	@bin/release hashrelease publish

hashrelease-svr-gc: bin/release
	@bin/release hashrelease garbage-collect

###############################################################################
# Release
###############################################################################
.PHONY: release-notes
release-notes: bin/release var-require-all-GITHUB_TOKEN
	@bin/release release generate-release-notes
