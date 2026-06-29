include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/webhooks

###############################################################################
# include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

clean:
	rm -rf bin

###############################################################################
# UTs
###############################################################################
ci: static-checks ut
ut:
	mkdir -p report
	$(DOCKER_GO_BUILD) gotestsum --junitfile report/webhooks_ut.xml -- ./... -coverprofile coverage.profile -race -count 1

gen-mocks:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'mockery'
