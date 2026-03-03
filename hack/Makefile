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

.PHONY: clean
clean:
	rm -rf $(BINDIR)
	find . -name 'coverprofile.out' -type f -delete

###############################################################################
# Building the binary
###############################################################################

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
	$(DOCKER_RUN) $(CALICO_BUILD) \
		sh -c 'cd /go/src/$(PACKAGE_NAME) && \
		       go run ./cmd/calico-selector set-name "has(a)"&& \
               go run ./cmd/calico-selector print-tree "a == \"b\" || has(d) || has(e) && has(g)"'

st:
	@echo "No STs available"

###############################################################################
# Shell script tests
###############################################################################
.PHONY: shell-test
shell-test:
	bash cherry-pick-pull_test.sh

###############################################################################
# CI
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean static-checks test shell-test
