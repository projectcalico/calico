include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/hack

###############################################################################
# Download and include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################

BINDIR?=bin

# Create a list of files upon which the generated file depends, skip the generated file itself
APIS_SRCS := $(filter-out ./lib/apis/v3/zz_generated.deepcopy.go, $(wildcard ./lib/apis/v3/*.go))

.PHONY: clean
clean:
	rm -rf $(BINDIR)
	find . -name '*.coverprofile' -type f -delete

###############################################################################
# Building the binary
###############################################################################


###############################################################################
# Static checks
###############################################################################
LINT_ARGS += --disable gosimple,unused,errcheck,ineffassign,staticcheck

###############################################################################
# Tests
###############################################################################

WHAT?=.
GINKGO_FOCUS?=.*

.PHONY:ut
## Run the fast set of unit tests in a container.
ut:
	$(DOCKER_RUN) --privileged $(CALICO_BUILD) \
		sh -c 'cd /go/src/$(PACKAGE_NAME) && go test ./...'

fv:
	@echo "No FVs available"

st:
	@echo "No STs available"

###############################################################################
# CI
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean static-checks test
