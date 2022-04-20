# If ../metadata.mk exists, we're running this logic from within the calico repository.
# If it does not, then we're in the api repo and we should use the local metadata.mk.
ifneq ("$(wildcard ../metadata.mk)", "")
include ../metadata.mk
else
include ./metadata.mk
endif

PACKAGE_NAME    ?= github.com/projectcalico/api
LOCAL_CHECKS     = lint-cache-dir goimports check-copyright

BINDIR ?= bin
BUILD_DIR ?= build
TOP_SRC_DIRS = pkg

##############################################################################
# Download and include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
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
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e GOCACHE=/go-cache \
		$(GOARCH_FLAGS) \
		-e GOPATH=/go \
		-e OS=$(BUILDOS) \
		-e GOOS=$(BUILDOS) \
		-e GOFLAGS=$(GOFLAGS) \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
		-v $(CURDIR)/../.go-pkg-cache:/go-cache:rw \
		-w /go/src/$(PACKAGE_NAME)

build: gen-files examples

###############################################################################
# This section contains the code generation stuff
###############################################################################
# Regenerate all files if the gen exes changed or any "types.go" files changed
.PHONY: gen-files
gen-files .generate_files: lint-cache-dir clean-generated
	# Generate defaults
	$(DOCKER_RUN) $(CALICO_BUILD) \
	   sh -c '$(GIT_CONFIG_SSH) defaulter-gen \
		--v 1 --logtostderr \
		--go-header-file "/go/src/$(PACKAGE_NAME)/hack/boilerplate/boilerplate.go.txt" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/projectcalico/v3" \
		--extra-peer-dirs "$(PACKAGE_NAME)/pkg/apis/projectcalico/v3" \
		--output-file-base "zz_generated.defaults"'
	# Generate deep copies
	$(DOCKER_RUN) $(CALICO_BUILD) \
	   sh -c '$(GIT_CONFIG_SSH) deepcopy-gen \
		--v 1 --logtostderr \
		--go-header-file "/go/src/$(PACKAGE_NAME)/hack/boilerplate/boilerplate.go.txt" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/projectcalico/v3" \
		--bounding-dirs $(PACKAGE_NAME) \
		--output-file-base zz_generated.deepcopy'

	# generate all pkg/client contents
	$(DOCKER_RUN) $(CALICO_BUILD) \
	   sh -c '$(GIT_CONFIG_SSH) $(BUILD_DIR)/update-client-gen.sh'

	# generate openapi
	$(DOCKER_RUN) $(CALICO_BUILD) \
	   sh -c '$(GIT_CONFIG_SSH) openapi-gen \
		--v 1 --logtostderr \
		--go-header-file "/go/src/$(PACKAGE_NAME)/hack/boilerplate/boilerplate.go.txt" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/projectcalico/v3,k8s.io/api/core/v1,k8s.io/api/networking/v1,k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/apimachinery/pkg/version,k8s.io/apimachinery/pkg/runtime,k8s.io/apimachinery/pkg/util/intstr,$(PACKAGE_NAME)/pkg/lib/numorstring" \
		--output-package "$(PACKAGE_NAME)/pkg/openapi"'

	touch .generate_files
	$(MAKE) fix

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
	rm -rf pkg/client/clientset_generated pkg/client/informers_generated pkg/client/listers_generated pkg/openapi pkg/lib/numorstring/openapi_generated.go

clean-bin:
	rm -rf $(BINDIR) \
	    .generate_execs \

.PHONY: examples
examples: bin/list-gnp

bin/list-gnp: examples/list-gnp/main.go
	@echo Building list-gnp example binary...
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
	   	go build -v -o $@ -v $(LDFLAGS) "examples/list-gnp/main.go"' 

WHAT?=.
GINKGO_FOCUS?=.*

.PHONY:ut
ut:
	$(DOCKER_RUN) --privileged $(CALICO_BUILD) \
		sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -r -focus="$(GINKGO_FOCUS)" $(WHAT)'

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
# Static checks
###############################################################################
## Perform static checks on the code.
# TODO: re-enable these linters !
LINT_ARGS := --disable gosimple,govet,structcheck,errcheck,goimports,unused,ineffassign,staticcheck,deadcode,typecheck --timeout 5m

###############################################################################
# CI
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean check-generated-files build static-checks ut
