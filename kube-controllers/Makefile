include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/kube-controllers

# The flannel-migration-controller is kept as a standalone image because the
# flannel migration FV tests need kubectl inside the container, and the
# combined calico/calico image does not ship kubectl.
FLANNEL_MIGRATION_IMAGE ?= flannel-migration-controller
BUILD_IMAGES            ?= $(FLANNEL_MIGRATION_IMAGE)

###############################################################################
# Download and include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

## SRC_FILES is auto-populated from deps.txt by lib.Makefile.
FLANNEL_MIGRATION_CONTAINER_CREATED=.image.created-flannel-migration-$(ARCH)

BINDIR=bin

###############################################################################

## Removes all build artifacts.
clean:
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -f report/*.xml
	rm -f tests/fv/fv.test
	rm -rf bin image.created-$(ARCH) build report/*.xml release-notes-*
	-docker image rm -f $$(docker images $(FLANNEL_MIGRATION_IMAGE) -a -q)

###############################################################################
# Building the binary
###############################################################################
# The kube-controllers and check-status binaries are only built standalone for
# the flannel-migration image. The main kube-controllers ships in the uber
# calico/calico image.
build: $(BINDIR)/kube-controllers-linux-$(ARCH) $(BINDIR)/check-status-linux-$(ARCH)

$(BINDIR)/kube-controllers-linux-$(ARCH): $(SRC_FILES)
	$(call build_binary, ./cmd/kube-controllers/, $@)

$(BINDIR)/check-status-linux-$(ARCH): $(SRC_FILES)
	$(call build_binary, ./cmd/check-status, $@)

$(BINDIR)/kubectl-$(ARCH):
	curl -sSf -L --retry 5 -o $@ https://dl.k8s.io/release/$(K8S_VERSION)/bin/linux/$(ARCH)/kubectl
	chmod +x $@

###############################################################################
# Building the image
###############################################################################
image: $(FLANNEL_MIGRATION_CONTAINER_CREATED)

$(FLANNEL_MIGRATION_CONTAINER_CREATED): docker-image/flannel-migration/Dockerfile $(BINDIR)/kube-controllers-linux-$(ARCH) $(BINDIR)/check-status-linux-$(ARCH) $(BINDIR)/kubectl-$(ARCH) | register
	cp ../LICENSE.md $(BINDIR)/LICENSE
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(FLANNEL_MIGRATION_IMAGE):latest-$(ARCH) -f docker-image/flannel-migration/Dockerfile .
	touch $@

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

## Run the unit tests in a container.
# kube-controllers tests use the combined calico/calico image (loaded from the
# uber-image prerequisite in CI, or built locally via `make -C cmd/calico image`).
# Flannel-migration FV tests need kubectl inside the container, which the
# combined image does not ship, so they continue to use a dedicated image.
test: ut
ut fv: $(TEST_BINARIES) $(FLANNEL_MIGRATION_CONTAINER_CREATED) setup-envtest
	KUBE_IMAGE=$(CALICO_BUILD) \
		   ETCD_IMAGE=$(ETCD_IMAGE) \
		   CALICO_API_GROUP=$(CALICO_API_GROUP) \
		   CONTAINER_NAME=calico/calico:latest-$(ARCH) \
		   MIGRATION_CONTAINER_NAME=$(FLANNEL_MIGRATION_IMAGE):latest-$(ARCH) \
		   CRDS=$(REPO_ROOT)/$(CALICO_CRD_PATH) \
		   CERTS_PATH=$(CERTS_PATH) \
		   KUBEBUILDER_ASSETS=$$(ls -d $(ENVTEST_DIR)/k8s/*-$(BUILDOS)-$(BUILDARCH) | tail -1) \
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
.PHONY: ci
ci: clean mod-download static-checks ut
