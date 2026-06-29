include ../metadata.mk

PACKAGE_NAME   ?= github.com/projectcalico/calico/guardian

##############################################################################
# Include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

BRANCH_NAME ?= $(PIN_BRANCH)

BINDIR        ?= bin
## SRC_FILES is auto-populated from deps.txt by lib.Makefile.

gen-mocks:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'mockery'

gen-files: gen-mocks

#############################################
# Run unit level tests
#############################################
.PHONY: ut
## Run only Unit Tests.
ut:
	mkdir -p report
	$(DOCKER_GO_BUILD) gotestsum --junitfile report/guardian_ut.xml -- -race ./pkg/... -cover -count 1

.PHONY: fv
## Run only Unit Tests.
fv:
	mkdir -p report
	$(DOCKER_GO_BUILD) gotestsum --junitfile report/guardian_fv.xml -- -race ./tests/fv/... -cover -count 1

##########################################################################################
# CI
##########################################################################################
.PHONY: ci
## Run all CI steps for build and test, likely other targets.
ci: static-checks ut fv

clean:
	rm -rf $(BINDIR)
