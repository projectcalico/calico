include ../metadata.mk

PACKAGE_NAME    ?= github.com/projectcalico/calico/key-cert-provisioner

TEST_SIGNER_IMAGE ?= test-signer

###############################################################################
# Download and include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################
# BUILD BINARY
###############################################################################
BINDIR=bin

.PHONY: build
build: $(BINDIR)/test-signer-$(ARCH)

.PHONY: $(BINDIR)/test-signer-$(ARCH)
$(BINDIR)/test-signer-$(ARCH):
	$(call build_binary, test-signer/test-signer.go, $@)

###############################################################################
# BUILD IMAGE
###############################################################################
SIGNER_CREATED=.signer.created-$(ARCH)

.PHONY: image
image: $(SIGNER_CREATED)

$(SIGNER_CREATED): $(BINDIR)/test-signer-$(ARCH)
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(TEST_SIGNER_IMAGE):latest-$(ARCH) -f test-signer/Dockerfile .
	touch $@

###############################################################################
# CI/CD
###############################################################################
ut:
	mkdir -p report
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			gotestsum --junitfile report/key_cert_provisioner_ut.xml -- ./...'

ci: clean static-checks ut

clean:
	rm -f Makefile.common*
	rm -rf .go-pkg-cache bin .*.created*
	-docker image rm -f $$(docker images $(TEST_SIGNER_IMAGE) -a -q)
