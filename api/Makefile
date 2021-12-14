PACKAGE_NAME    ?= github.com/projectcalico/api
GO_BUILD_VER    ?= v0.59
GOMOD_VENDOR    := false
GIT_USE_SSH      = true
LOCAL_CHECKS     = lint-cache-dir goimports check-copyright

BINDIR ?= bin
BUILD_DIR ?= build
TOP_SRC_DIRS = pkg

ORGANIZATION=projectcalico
SEMAPHORE_PROJECT_ID?=$(SEMAPHORE_API_PROJECT_ID)

# Used so semaphore can trigger the update pin pipelines in projects that have this project as a dependency.
SEMAPHORE_AUTO_PIN_UPDATE_PROJECT_IDS=$(SEMAPHORE_LIBCALICO_GO_PROJECT_ID)

##############################################################################
# Download and include Makefile.common before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
MAKE_BRANCH?=$(GO_BUILD_VER)
MAKE_REPO?=https://raw.githubusercontent.com/projectcalico/go-build/$(MAKE_BRANCH)

Makefile.common: Makefile.common.$(MAKE_BRANCH)
	cp "$<" "$@"
Makefile.common.$(MAKE_BRANCH):
	# Clean up any files downloaded from other branches so they don't accumulate.
	rm -f Makefile.common.*
	curl --fail $(MAKE_REPO)/Makefile.common -o "$@"

include Makefile.common

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
	rm -rf .lint-cache Makefile.common*

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
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
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
ci: clean check-generated-files static-checks ut
