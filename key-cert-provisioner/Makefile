include ../metadata.mk

PACKAGE_NAME    ?= github.com/projectcalico/calico/key-cert-provisioner

#############################################
# Env vars related to packaging and releasing
#############################################

KEY_CERT_PROVISIONER_IMAGE ?=key-cert-provisioner
TEST_SIGNER_IMAGE          ?=test-signer
BUILD_IMAGES               ?=$(KEY_CERT_PROVISIONER_IMAGE) $(TEST_SIGNER_IMAGE)

PUSH_IMAGES           ?= $(foreach registry,$(DEV_REGISTRIES),$(addprefix $(registry)/,$(BUILD_IMAGES)))
RELEASE_IMAGES        ?= $(foreach registry,$(RELEASE_REGISTRIES),$(addprefix $(registry)/,$(BUILD_IMAGES)))

###############################################################################
# Download and include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################
# BUILD BINARY
###############################################################################
FIPS ?= false

ifeq ($(FIPS),true)
KEY_CERT_PROVISIONER_CREATED=.key-cert-provisioner.created-$(ARCH)-fips
VALIDARCHES=amd64
BINDIR=bin/$(ARCH)-fips
LATEST_TAG=latest-fips
else
KEY_CERT_PROVISIONER_CREATED=.key-cert-provisioner.created-$(ARCH)
BINDIR=bin
LATEST_TAG=latest
endif

.PHONY: build
build: $(BINDIR)/key-cert-provisioner-$(ARCH) $(BINDIR)/test-signer-$(ARCH)

.PHONY: $(BINDIR)/key-cert-provisioner-$(ARCH)
$(BINDIR)/key-cert-provisioner-$(ARCH):
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, cmd/main.go, $@)
else
	$(call build_binary, cmd/main.go, $@)
endif

.PHONY: $(BINDIR)/test-signer-$(ARCH)
$(BINDIR)/test-signer-$(ARCH):
	$(call build_binary, test-signer/test-signer.go, $@)

###############################################################################
# BUILD IMAGE
###############################################################################
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES)) sub-image-fips-amd64
sub-image-%:
	$(MAKE) image ARCH=$*
sub-image-fips-%:
	$(MAKE) image FIPS=true ARCH=$*

SIGNER_CREATED=.signer.created-$(ARCH)

.PHONY: image
image: $(KEY_CERT_PROVISIONER_CREATED) $(SIGNER_CREATED)
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest

$(KEY_CERT_PROVISIONER_CREATED): $(BINDIR)/key-cert-provisioner-$(ARCH)
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(KEY_CERT_PROVISIONER_IMAGE):$(LATEST_TAG)-$(ARCH) -f Dockerfile .
	touch $@

$(SIGNER_CREATED): $(BINDIR)/test-signer-$(ARCH)
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(TEST_SIGNER_IMAGE):latest-$(ARCH) -f Dockerfile .
	touch $@

###############################################################################
# CI/CD
###############################################################################
ut: build
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			go test ./...'

ci: clean static-checks ut

cd: image-all cd-common

clean:
	rm -f Makefile.common*
	rm -rf .go-pkg-cache bin .*.created*
	-docker image rm -f $$(docker images $(KEY_CERT_PROVISIONER_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(TEST_SIGNER_IMAGE) -a -q)

