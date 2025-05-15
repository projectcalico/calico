include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/lib

###############################################################################
# include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

gen-mocks:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'cd httpmachinery && mockery'

gen-files: gen-mocks
