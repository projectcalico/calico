include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/release

include ../lib.Makefile

LINT_ARGS += --build-tags fv

.PHONY: build
build: bin/release

# The tool logs to the directory it ran from, so clean the repo root too.
clean:
	@rm -rf ./bin ./output ./_output ./report ./tmp ./_logs
	@rm -f ./internal/defaults/metadata.mk
	@find .. -maxdepth 1 -name '*.log' -delete
	@find . -name '*.log' -delete
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

###############################################################################
# Tests
###############################################################################
GOTESTSUM          := $(if $(DOCKER_GO_BUILD),gotestsum,bin/gotestsum)
# An empty DOCKER_GO_BUILD runs the tests on the host.
UT_RUN             := $(DOCKER_GO_BUILD) $(GOTESTSUM)
FV_RUN             = $(if $(DOCKER_GO_BUILD),$(DOCKER_RUN) $(FV_IMAGE)) $(GOTESTSUM)

# Each test layer runs only the relevant tests for that layer.
UNIT_TEST_PACKAGES := $(patsubst %/,%,$(sort $(dir $(shell find . -name '*.go' -not -path './pkg/postrelease/*'))))
FV_TEST_PACKAGES   := $(patsubst %/,%,$(sort $(dir $(shell find . -name '*_fv_test.go'))))

# FV Images and required tools for functional verification tests
FV_IMAGE_PACKAGES  := git-core gnupg2 make rpm rpm-build rpm-sign tar
FV_IMAGE           := calico/release-fv:$(GO_BUILD_VER)
FV_TOOLS           := git gpg make rpmkeys rpmbuild rpmsign tar

bin/gotestsum:
	@GOBIN=$(CURDIR)/bin go install gotest.tools/gotestsum@$(GOTESTSUM_VERSION)

.PHONY: ut
ut: $(filter bin/%,$(GOTESTSUM))
	@mkdir -p report
	@$(UT_RUN) --junitfile report/unit-tests.xml \
		-- -coverprofile=report/coverage.out $(UNIT_TEST_PACKAGES)

.PHONY: fv
fv: fv/deps $(filter bin/%,$(GOTESTSUM))
	@mkdir -p report
	@$(FV_RUN) --junitfile report/fv-tests.xml \
		-- -tags fv $(FV_TEST_PACKAGES)

fv/deps:
ifneq ($(DOCKER_GO_BUILD),)
	@docker build -q -t $(FV_IMAGE) --build-arg CALICO_BUILD=$(CALICO_BUILD) \
		--build-arg PACKAGES="$(FV_IMAGE_PACKAGES)" - < fv.Dockerfile >/dev/null
else
	$(eval missing := $(strip $(foreach t,$(FV_TOOLS),$(if $(shell command -v $(t)),,$(t)))))
	$(if $(missing),$(warning fv tests needing $(missing) will skip; install with: dnf install -y $(FV_IMAGE_PACKAGES)))
endif

.PHONY: st st/hashrelease st/release
st: st/hashrelease st/release

st/hashrelease: var-require-all-HASHRELEASE_SERVER_BUCKET
	PLAN=true $(MAKE) hashrelease
	LOCAL=true BRANCH_CHECK=false $(MAKE) hashrelease

st/release:
	PLAN=true $(MAKE) -C ../ release release-publish

###############################################################################
# Checks
###############################################################################
# bin/release tracks only release/ sources, so rebuild it to pick up the operator's
# component list. Clearing MAKEFLAGS keeps an outer -C's -w directory lines out of
# the parsed image list.
.PHONY: check-operator-images
check-operator-images:
	@$(MAKE) --no-print-directory --always-make bin/release
	@MAKEFLAGS= bin/release images check-operator

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
ci: static-checks ut fv

###############################################################################
# Hashrelease
###############################################################################
.PHONY: hashrelease hashrelease-build hashrelease-publish
hashrelease: hashrelease-build hashrelease-publish

# Ensures helm is in the bin dir relative to repo root
../bin/helm:
	@$(MAKE) -C ../ helm

hashrelease-build: bin/release
	@bin/release hashrelease build

hashrelease-publish: bin/release ../bin/helm
	@bin/release hashrelease publish

hashrelease-svr-gc: bin/release
	@bin/release hashrelease garbage-collect

###############################################################################
# Release
###############################################################################
.PHONY: release-notes
release-notes: bin/release var-require-all-GITHUB_TOKEN
	@bin/release release generate-release-notes
