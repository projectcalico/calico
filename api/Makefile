# The tests in this directory use the projectcalico.org/v3 API group for CRDs.
CALICO_API_GROUP ?= projectcalico.org/v3

# If ../metadata.mk exists, we're running this logic from within the calico repository.
# If it does not, then we're in the api repo and we should use the local metadata.mk.
ifneq ("$(wildcard ../metadata.mk)", "")
include ../metadata.mk
else
include ./metadata.mk
endif

PACKAGE_NAME    ?= github.com/projectcalico/api
LOCAL_CHECKS     = lint-cache-dir check-copyright

BINDIR ?= bin
BUILD_DIR ?= build
TOP_SRC_DIRS = pkg
KIND_CONFIG = $(KIND_DIR)/kind-single.config

##############################################################################
# Download and include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
# The api container mounts at /go/src/$(PACKAGE_NAME), not the default calico
# repo path.  Override DOCKER_GIT_WORK_TREE so that git worktree support in
# lib.Makefile sets GIT_WORK_TREE to the correct container path.
DOCKER_GIT_WORK_TREE := /go/src/$(PACKAGE_NAME)

# If ../lib.Makefile exists, we're running this logic from within the calico repository.
# If it does not, then we're in the api repo and should use the local lib.Makefile.
ifneq ("$(wildcard ../lib.Makefile)", "")
include ../lib.Makefile
else
include ./lib.Makefile
endif

# Override DOCKER_RUN from lib.Makefile. We need to trick this particular directory to think
# that its package is github.com/projectcalico/api for easier mirroring.
DOCKER_RUN := mkdir -p ../.go-pkg-cache bin $(GOMOD_CACHE) && \
	docker run --rm \
		--net=host \
		--init \
		$(EXTRA_DOCKER_ARGS) \
		$(DOCKER_GIT_WORKTREE_ARGS) \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e GOCACHE=/go-cache \
		$(GOARCH_FLAGS) \
		-e GOPATH=/go \
		-e OS=$(BUILDOS) \
		-e GOOS=$(BUILDOS) \
		-e "GOFLAGS=$(GOFLAGS)" \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
		-v $(CURDIR)/../.go-pkg-cache:/go-cache:rw \
		-w /go/src/$(PACKAGE_NAME)

build: gen-files examples

###############################################################################
# This section contains the code generation stuff
###############################################################################
# Regenerate all files if the gen exes changed or any "types.go" files changed
.PHONY: gen-files
generate gen-files .generate_files: lint-cache-dir clean-generated
	# Run generation script.
	$(DOCKER_RUN) \
		-e PACKAGE_NAME=$(PACKAGE_NAME) \
		$(CALICO_BUILD) \
		sh -c '$(BUILD_DIR)/generate.sh'

	# Run prettier to fix CRD indentation.
	docker run --rm --user $(id -u):$(id -g) -v $(CURDIR)/config/crd/:/work/config/crd/ tmknom/prettier --write --parser=yaml /work

	# Patch in manual tweaks to the generated CRDs.
	patch --no-backup-if-mismatch -p2 < patches/0001-Add-nullable-to-IPAM-block-allocations-field.patch

	touch .generate_files
	$(MAKE) fix

# Would be nice to use the monorepo's more-thorough fix target here but,
# once the API package is exported to its own repo, the monorepo's scripts are
# not available.
fix:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'find . -iname "*.go" ! -wholename "./vendor/*" | xargs goimports -w -local github.com/projectcalico/calico/'


.PHONY: lint-cache-dir
lint-cache-dir:
	mkdir -p $(CURDIR)/.lint-cache

.PHONY: check-copyright
check-copyright:
	@hack/check-copyright.sh

.PHONY: clean
clean: clean-bin
	rm -rf .lint-cache

clean-generated:
	rm -f .generate_files
	find $(TOP_SRC_DIRS) -name zz_generated* -exec rm {} \;
	# rollback changes to the generated clientset directories
	# find $(TOP_SRC_DIRS) -type d -name *_generated -exec rm -rf {} \;
	rm -rf pkg/client/clientset_generated pkg/client/informers_generated pkg/client/listers_generated pkg/client/applyconfiguration_generated pkg/openapi

clean-bin:
	rm -rf $(BINDIR) \
	    .generate_execs \

.PHONY: examples
examples: bin/list-gnp

bin/list-gnp: examples/list-gnp/main.go
	@echo Building list-gnp example binary...
	$(call build_binary, examples/list-gnp/main.go, $@)

WHAT?=.
GINKGO_FOCUS?=.*

.PHONY:ut
ut: kind-cluster-create
	mkdir -p report
	$(DOCKER_RUN) \
		--privileged \
		-e KUBECONFIG=/kubeconfig.yaml \
		-v $(KIND_KUBECONFIG):/kubeconfig.yaml \
		$(CALICO_BUILD) \
		sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -r --junit-report=api_ut.xml --output-dir=report/ -focus="$(GINKGO_FOCUS)" $(WHAT)'

## Run CRD validation tests using envtest (no kind cluster required)
.PHONY: ut-validation
ut-validation: setup-envtest
	$(DOCKER_RUN) \
		-v $$(ls -d $(ENVTEST_DIR)/k8s/*-$(BUILDOS)-$(BUILDARCH) | tail -1):/envtest:ro \
		-e KUBEBUILDER_ASSETS=/envtest \
		$(CALICO_BUILD) \
		sh -c 'go test -count=1 ./...'

## Check if generated files are out of date
.PHONY: check-generated-files
check-generated-files: .generate_files
	if (git describe --tags --dirty | grep -c dirty >/dev/null); then \
	  echo "Generated files are out of date."; \
	  false; \
	else \
	  echo "Generated files are up to date."; \
	fi

###############################################################################
# CI
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean check-generated-files build static-checks ut
