include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/goldmane
IMAGE_BUILD_MARKER = goldmane_container-$(ARCH).created

###############################################################################
# include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

.PHONY: image build
image: $(IMAGE_BUILD_MARKER)
build: bin/goldmane-$(ARCH)
clean:
	rm -rf bin
	rm -f $(IMAGE_BUILD_MARKER)

image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

# Build goldmane image.
calico/goldmane: $(IMAGE_BUILD_MARKER)
$(IMAGE_BUILD_MARKER): bin/goldmane-$(ARCH)
	$(DOCKER_BUILD) --build-arg TARGETARCH=$(ARCH) -t calico/goldmane:latest-$(ARCH) -f docker/Dockerfile .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=calico/goldmane VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

bin/goldmane-$(ARCH): $(shell find . -name '*.go')
	$(call build_binary, $(PACKAGE_NAME)/cmd/, $@)

# Build the testserver image.
.PHONY: testserver
calico/flowgen: bin/flowgen
	docker build -t calico/flowgen -f docker/flowgen/Dockerfile .

bin/flowgen: $(shell find . -name '*.go')
	$(call build_binary, $(PACKAGE_NAME)/cmd/flowgen, $@)

# Update protobuf generation.
protobuf proto/api.pb.go: proto/api.proto
	docker run --rm --user $(LOCAL_USER_ID):$(LOCAL_GROUP_ID) \
	  	  -v $(CURDIR):/code -v $(CURDIR)/proto:/src:rw \
	  	      $(PROTOC_CONTAINER) \
	  	      --gogofaster_out=\
	Mgoogle/protobuf/any.proto=github.com/gogo/protobuf/types,\
	Mgoogle/protobuf/duration.proto=github.com/gogo/protobuf/types,\
	Mgoogle/protobuf/struct.proto=github.com/gogo/protobuf/types,\
	Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types,\
	Mgoogle/protobuf/wrappers.proto=github.com/gogo/protobuf/types,\
	plugins=grpc:. \
	api.proto
	$(MAKE) fix-changed

###############################################################################
# Release
###############################################################################
release-build: .release-$(VERSION).created
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=latest

release-verify: release-prereqs
	@echo "Nothing to do"

release-publish: release-prereqs release-verify .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	$(MAKE) FIPS=true push-images-to-registries push-manifests IMAGETAG=$(VERSION)-fips RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)

	# Push Windows images.
	$(MAKE) release-windows IMAGETAG=$(VERSION) CONFIRM=$(CONFIRM)
	touch $@
