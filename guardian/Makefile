include ../metadata.mk

PACKAGE_NAME   ?= github.com/projectcalico/calico/guardian

#############################################
# Env vars related to packaging and releasing
#############################################
COMPONENTS            ?=guardian
GUARDIAN_IMAGE        ?=guardian
BUILD_IMAGES          ?=$(GUARDIAN_IMAGE)

##############################################################################
# Include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

##########################################################################################
# Define some constants
##########################################################################################
BRANCH_NAME ?= $(PIN_BRANCH)

BINDIR        ?= bin
SRC_FILES = $(shell find . -name '*.go') \
		$(shell find ../api/pkg -name '*.go') \
		$(shell find ../libcalico-go/lib/logutils -name '*.go')

#############################################
# Env vars related to building
#############################################

# Flags for building the binaries.
#
# We use -X to insert the version information into the placeholder variables
# in the version package.
LDFLAGS = -X $(PACKAGE_NAME)/pkg/version.BuildVersion=$(GIT_VERSION) \
			  -X $(PACKAGE_NAME)/pkg/version.BuildDate=$(DATE) \
			  -X $(PACKAGE_NAME)/pkg/version.GitDescription=$(GIT_DESCRIPTION) \
			  -X $(PACKAGE_NAME)/pkg/version.GitRevision=$(GIT_COMMIT) \

##########################################################################################
# BUILD
##########################################################################################
build: $(BINDIR)/guardian-$(ARCH)

.PHONY: $(BINDIR)/guardian-$(ARCH)
$(BINDIR)/guardian-$(ARCH): $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/guardian/main.go, $@)
else
	$(call build_binary, ./cmd/guardian/main.go, $@)
endif

gen-mocks:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'mockery'

gen-files: gen-mocks

#############################################
# Docker Image
#############################################
GUARDIAN_CONTAINER_CREATED=.guardian.created-$(ARCH)

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

$(GUARDIAN_IMAGE): $(GUARDIAN_CONTAINER_CREATED)
$(GUARDIAN_CONTAINER_CREATED): docker-image/guardian/Dockerfile $(BINDIR)/guardian-$(ARCH)
	$(DOCKER_BUILD) -t $(GUARDIAN_IMAGE):latest-$(ARCH) -f docker-image/guardian/Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest BUILD_IMAGES=$(GUARDIAN_IMAGE)
	touch $@

#############################################
# Run unit level tests
#############################################
.PHONY: ut
## Run only Unit Tests.
ut:
	$(DOCKER_GO_BUILD) go test ./... -cover -count 1

##########################################################################################
# CI/CD
##########################################################################################
.PHONY: ci cd

#############################################
# Run CI cycle - build, test, etc.
#############################################
## Run all CI steps for build and test, likely other targets.
ci: static-checks ut

clean:

#############################################
# Deploy images to registry
#############################################
## Run all CD steps, normally pushing images out to registries.
cd: image-all cd-common

release-build: .release-$(VERSION).created
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=latest
	touch $@

release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@
