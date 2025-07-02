include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/validatingwebhook
IMAGE_BUILD_MARKER = webhook_container-$(ARCH).created

# Configure variables used by ci/cd common targets from lib.Makefile.
BUILD_IMAGES=webhook

###############################################################################
# include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

# Full set of binaries to build.
BINARIES=bin/webhook-$(ARCH)

.PHONY: image build
image: $(IMAGE_BUILD_MARKER)
build: $(BINARIES)
clean:
	rm -rf bin
	rm -f $(IMAGE_BUILD_MARKER)

image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

# Build webhook image.
webhook calico/webhook: $(IMAGE_BUILD_MARKER)
$(IMAGE_BUILD_MARKER): $(BINARIES) bin/LICENSE
	$(DOCKER_BUILD) --build-arg TARGETARCH=$(ARCH) -t webhook:latest-$(ARCH) -f docker/Dockerfile .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(BUILD_IMAGES) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

bin/webhook-$(ARCH): $(shell find . -name '*.go')
	$(call build_binary, $(PACKAGE_NAME)/cmd/, $@)

bin/LICENSE: ../LICENSE.md
	cp ../LICENSE.md $@

###############################################################################
# Generate files
###############################################################################
GENERATED_FILES=proto/api.pb.go
gen-files: $(GENERATED_FILES) gen-mocks

###############################################################################
# UTs
###############################################################################
ci: static-checks ut
ut:
	$(DOCKER_GO_BUILD) go test ./... -coverprofile coverage.profile -race -count 1

gen-mocks:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'mockery'

###############################################################################
# Release
###############################################################################
## Deploys images to registry
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
