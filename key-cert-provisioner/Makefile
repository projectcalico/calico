# Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

PACKAGE_NAME    ?= github.com/tigera/key-cert-provisioner

GO_BUILD_VER    ?= v0.90
GIT_USE_SSH      = true

ORGANIZATION=tigera
SEMAPHORE_PROJECT_ID?=$(SEMAPHORE_KEY_CERT_PROVISIONER_PROJECT_ID)

ARCHES=amd64 arm64

RELEASE_BRANCH_PREFIX ?= release
DEV_TAG_SUFFIX        ?= 0.dev

DEV_REGISTRIES        ?= quay.io
RELEASE_REGISTRIES    ?= quay.io

KEY_CERT_PROVISIONER_IMAGE ?=tigera/key-cert-provisioner
TEST_SIGNER_IMAGE          ?=tigera/test-signer
BUILD_IMAGES               ?=$(KEY_CERT_PROVISIONER_IMAGE) $(TEST_SIGNER_IMAGE)

PUSH_IMAGES           ?= $(foreach registry,$(DEV_REGISTRIES),$(addprefix $(registry)/,$(BUILD_IMAGES)))
RELEASE_IMAGES        ?= $(foreach registry,$(RELEASE_REGISTRIES),$(addprefix $(registry)/,$(BUILD_IMAGES)))

GO_FILES= $(shell sh -c "find pkg cmd -name \\*.go")
EXTRA_DOCKER_ARGS += -e GOPRIVATE=github.com/tigera/*

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

GOFLAGS = -buildvcs=false
include Makefile.common

###############################################################################
# Build
###############################################################################
.PHONY: build
build: bin/key-cert-provisioner-$(ARCH) bin/test-signer-$(ARCH)

.PHONY: bin/key-cert-provisioner-$(ARCH)
bin/key-cert-provisioner-$(ARCH): $(GO_FILES)
	$(DOCKER_GO_BUILD) \
        sh -c '$(GIT_CONFIG_SSH) go build -o $@ -ldflags "$(LDFLAGS) -s -w" cmd/main.go'

.PHONY: bin/test-signer-$(ARCH)
bin/test-signer-$(ARCH): $(GO_FILES)
	$(DOCKER_GO_BUILD) \
        sh -c '$(GIT_CONFIG_SSH) go build -o $@ -ldflags "$(LDFLAGS) -s -w" test-signer/test-signer.go'

###############################################################################
# Image
###############################################################################
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: tigera/key-cert-provisioner tigera/test-signer-image

.PHONY: tigera/key-cert-provisioner
tigera/key-cert-provisioner: tigera/key-cert-provisioner-$(ARCH)
tigera/key-cert-provisioner-$(ARCH): build
	docker buildx build --load --platform=linux/$(ARCH) --pull \
		-t tigera/key-cert-provisioner:latest-$(ARCH) \
		-f Dockerfile .
ifeq ($(ARCH),amd64)
	docker tag tigera/key-cert-provisioner:latest-$(ARCH) tigera/key-cert-provisioner:latest
endif

.PHONY: tigera/test-signer-image
tigera/test-signer-image: bin/test-signer-$(ARCH)
	docker buildx build --load --platform=linux/$(ARCH) --pull \
		-t tigera/test-signer:latest-$(ARCH) \
		-f test-signer/Dockerfile .
ifeq ($(ARCH),amd64)
	docker tag tigera/test-signer:latest-$(ARCH) tigera/test-signer:latest
endif

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
	rm -rf .go-pkg-cache bin
	-docker image rm -f $$(docker images $(KEY_CERT_PROVISIONER_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(TEST_SIGNER_IMAGE) -a -q)
