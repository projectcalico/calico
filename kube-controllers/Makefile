include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/kube-controllers

###############################################################################
# Download and include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

## SRC_FILES is auto-populated from deps.txt by lib.Makefile.

BINDIR=bin

###############################################################################

## Removes all build artifacts.
clean:
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -f report/*.xml
	rm -f tests/fv/fv.test
	rm -rf bin image.created-$(ARCH) build report/*.xml release-notes-*

###############################################################################
# Building the binary
###############################################################################
# The kube-controllers and check-status binaries are only built standalone
# here for local development; in CI they ship inside the combined calico image.
build: $(BINDIR)/kube-controllers-linux-$(ARCH) $(BINDIR)/check-status-linux-$(ARCH)

$(BINDIR)/kube-controllers-linux-$(ARCH): $(SRC_FILES)
	$(call build_binary, ./cmd/kube-controllers/, $@)

$(BINDIR)/check-status-linux-$(ARCH): $(SRC_FILES)
	$(call build_binary, ./cmd/check-status, $@)

###############################################################################
# Static checks
###############################################################################
check-copyright:
	./check-copyrights.sh

###############################################################################
# Code generation
###############################################################################
.PHONY: gen-files
gen-files:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'controller-gen crd paths=./pkg/controllers/migration/... output:crd:dir=pkg/controllers/migration/crd/'

###############################################################################
# Tests
###############################################################################
ifeq ($(SEMAPHORE_GIT_REF_TYPE), pull-request)
# Determine the tests to run using the test spider tool, which emits a list of impacted packages.
MAYBE_WHAT=$(shell $(DOCKER_GO_BUILD) sh -c 'go run ../hack/test/spider -commit-range=${SEMAPHORE_GIT_COMMIT_RANGE} -filter-dir kube-controllers/')
else
# By default, run all tests.
MAYBE_WHAT=.
endif

# Filter the list of directories to only those that have tests.
ifneq ("$(MAYBE_WHAT)","")
WHAT=$(shell find $(MAYBE_WHAT) -name "*_test.go" | xargs dirname | sort -u)
endif

# The list of test binaries to build.
# We pre-build the test binary so that we can run it outside a container and allow it
# to interact with docker.
TEST_BINARIES=$(addsuffix /ut.test,$(WHAT))

# Install gotestsum using the version pinned by metadata.mk, building it with
# the Go toolchain from the calico/go-build container for consistency. The
# binary runs on the host because run-uts invokes test binaries outside the
# container so they can talk to docker.
bin/gotestsum:
	$(DOCKER_RUN) -e GOBIN=/go/src/$(PACKAGE_NAME)/bin/ $(CALICO_BUILD) go install gotest.tools/gotestsum@$(GOTESTSUM_VERSION)

## Run the unit tests in a container.
# kube-controllers tests use the combined calico/calico image (loaded from the
# calico-image prerequisite in CI, or built locally via the marker rule in
# lib.Makefile). CI invokes the *-no-prereqs targets directly so a missing
# cached image fails loudly instead of triggering a silent rebuild.
test: ut

.PHONY: ut fv ut-prereqs ut-no-prereqs
ut fv: ut-prereqs
	$(MAKE) ut-no-prereqs

ut-prereqs: $(REPO_ROOT)/cmd/calico/.image.created-$(ARCH)

ut-no-prereqs: $(TEST_BINARIES) setup-envtest bin/gotestsum
	KUBE_IMAGE=$(CALICO_BUILD) \
		   ETCD_IMAGE=$(ETCD_IMAGE) \
		   CALICO_API_GROUP=$(CALICO_API_GROUP) \
		   CONTAINER_NAME=calico/calico:latest-$(ARCH) \
		   CRDS=$(REPO_ROOT)/$(CALICO_CRD_PATH) \
		   CERTS_PATH=$(CERTS_PATH) \
		   KUBEBUILDER_ASSETS=$$(ls -d $(ENVTEST_DIR)/k8s/*-$(BUILDOS)-$(BUILDARCH) | tail -1) \
		   GOTESTSUM=$(abspath bin/gotestsum) \
		   ./run-uts $(WHAT)

# Produce test binaries for each package that needs them.
# ginkgo doesn't let you produce a single test binary with multiple packages.
# Only do this if there are .go files in the path.
%/ut.test: $(SRC_FILES)
	if [ $$(find ./$* -name '*.go' | wc -l) -gt 0 ]; then \
		$(DOCKER_RUN) -e CGO_ENABLED=0 $(CALICO_BUILD) go test ./$* -c -o $@; \
	else \
		echo "Skipping $* as it has no .go files in it"; \
	fi

###############################################################################
# CI
###############################################################################
.PHONY: ci ci-no-prereqs
ci: clean mod-download static-checks ut

# CI entry point: skips the calico image rebuild and runs static checks plus
# the unit tests. The image must be preloaded from the GCS cache.
ci-no-prereqs: mod-download static-checks ut-no-prereqs
