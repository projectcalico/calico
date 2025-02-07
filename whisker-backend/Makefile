include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/whisker-backend
IMAGE_BUILD_MARKER = whisker-backend-$(ARCH).created

###############################################################################
# include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

# Configure variables used by ci/cd common targets from lib.Makefile.
BUILD_IMAGES=whisker-backend

.PHONY: image build
image: $(IMAGE_BUILD_MARKER)
build: bin/whisker-backend-$(ARCH)
clean:
	rm -rf bin
	rm -f $(IMAGE_BUILD_MARKER)

image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

# Build whisker-backend image.
calico/whisker-backend: $(IMAGE_BUILD_MARKER)
$(IMAGE_BUILD_MARKER): bin/whisker-backend-$(ARCH)
	$(DOCKER_BUILD) --build-arg TARGETARCH=$(ARCH) -t whisker-backend:latest-$(ARCH) -f docker/Dockerfile .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(BUILD_IMAGES) VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

bin/whisker-backend-$(ARCH): $(shell find . -name '*.go') $(shell find ../lib/. -name '*.go')
	$(call build_binary, $(PACKAGE_NAME)/cmd/, $@)

# Build the testserver image.
.PHONY: testserver
calico/flowgen: bin/flowgen
	docker build -t calico/flowgen -f docker/flowgen/Dockerfile .

bin/flowgen: $(shell find . -name '*.go')
	$(call build_binary, $(PACKAGE_NAME)/cmd/flowgen, $@)

# Update protobuf generation.
protobuf proto/api.pb.go: proto/api.proto
	$(DOCKER_RUN) -v $(CURDIR):/code \
		$(CALICO_BUILD) sh -c 'protoc --proto_path=/code/proto --go_out=/code/proto --go-grpc_out=. --go_opt=paths=source_relative /code/proto/api.proto'
	$(MAKE) fix-changed

###############################################################################
# UTs
###############################################################################
ci: static-checks ut
ut:
	$(DOCKER_GO_BUILD) go test ./... -cover -count 1

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

release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)

	touch $@
