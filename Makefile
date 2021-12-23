PACKAGE_NAME = github.com/projectcalico/calico

include metadata.mk 
include lib.Makefile


DOCKER_RUN := mkdir -p ../.go-pkg-cache bin $(GOMOD_CACHE) && \
	docker run --rm \
		--net=host \
		--init \
		$(EXTRA_DOCKER_ARGS) \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e GOCACHE=/go-cache \
		$(GOARCH_FLAGS) \
		-e GOPATH=/go \
		-e OS=$(BUILDOS) \
		-e GOOS=$(BUILDOS) \
		-e GOFLAGS=$(GOFLAGS) \
		-v $(CURDIR):/go/src/github.com/projectcalico/calico:rw \
		-v $(CURDIR)/.go-pkg-cache:/go-cache:rw \
		-w /go/src/$(PACKAGE_NAME)

MAKE_DIRS=$(shell ls -d */)

clean:
	$(MAKE) -C api clean
	$(MAKE) -C apiserver clean
	$(MAKE) -C app-policy clean
	$(MAKE) -C calicoctl clean
	$(MAKE) -C cni-plugin clean
	$(MAKE) -C confd clean
	$(MAKE) -C felix clean
	$(MAKE) -C kube-controllers clean
	$(MAKE) -C libcalico-go clean
	$(MAKE) -C node clean
	$(MAKE) -C pod2daemon clean
	$(MAKE) -C typha clean

generate:
	$(MAKE) -C api gen-files
	$(MAKE) -C libcalico-go gen-files
	$(MAKE) -C felix gen-files
	$(MAKE) -C app-policy protobuf

# Build all Calico images for the current architecture.
image:
	$(MAKE) -C pod2daemon image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C calicoctl image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C cni-plugin image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C apiserver image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C kube-controllers image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C app-policy image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C typha image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C node image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)

###############################################################################
# Release logic below
###############################################################################

# Directory in which to put artifacts to be uploaded to the github release.
UPLOAD_DIR=_output/upload/$(GIT_VERSION)

# Set HELM_CHART_RELEASE if this is a helm-only release, to create a chart
# that has an appendix for diferentiation from earlier charts. This need not be set
# on most releases.
HELM_CHART_RELEASE=

BUILD_CMD=release-build
DRY_RUN=echo

# Define a multi-line string for the GitHub release body.
# We need to export it as an env var to properly format it.
# See here: https://stackoverflow.com/questions/649246/is-it-possible-to-create-a-multi-line-string-variable-in-a-makefile/5887751
define RELEASE_BODY
Release notes can be found at https://projectcalico.docs.tigera.io/archive/$(RELEASE_STREAM)/release-notes/

Attached to this release are the following artifacts:

- `release-v$(CALICO_VER).tgz`: docker images and kubernetes manifests.
- `calico-windows-v$(CALICO_VER).zip`: Calico for Windows.
- `tigera-operator-v$(CALICO_VER).tgz`: Calico Helm v3 chart.

endef
export RELEASE_BODY

# Build and publish a release. Has the following dependencies:
# - Current commit must be a release tag.
# - Requires ghr: https://github.com/tcnksm/ghr
# - Requires GITHUB_TOKEN environment variable set.
release: #ensure-tagged
ifeq (, $(shell which ghr))
	$(error Unable to find `ghr` in PATH, run this: go get -u github.com/tcnksm/ghr)
endif
	# Build all the images for the release, tagging them with the current 
	# git version. By this point, we have asserted that GIT_VERSION is a tag.
	$(MAKE) -C pod2daemon $(BUILD_CMD) VERSION=$(GIT_VERSION)
	$(MAKE) -C calicoctl $(BUILD_CMD) VERSION=$(GIT_VERSION)
	$(MAKE) -C cni-plugin $(BUILD_CMD) VERSION=$(GIT_VERSION)
	$(MAKE) -C apiserver $(BUILD_CMD) VERSION=$(GIT_VERSION)
	$(MAKE) -C kube-controllers $(BUILD_CMD) VERSION=$(GIT_VERSION)
	$(MAKE) -C app-policy $(BUILD_CMD) VERSION=$(GIT_VERSION)
	$(MAKE) -C typha $(BUILD_CMD) VERSION=$(GIT_VERSION)
	$(MAKE) -C node $(BUILD_CMD) VERSION=$(GIT_VERSION)
	$(MAKE) -C calico $(BUILD_CMD) VERSION=$(GIT_VERSION) CHART_RELEASE=$(HELM_CHART_RELEASE)

	# Ensure the reported version for the generated images is correct.
	# TODO

	# Create artifact paths. Everything in these directories will be 
	# uploaded as part of the GitHub release.
	rm -rf _output/release-$(GIT_VERSION) 
	mkdir -p _output/release-$(GIT_VERSION)/binaries
	mkdir -p _output/release-$(GIT_VERSION)/images
	mkdir -p _output/release-$(GIT_VERSION)/windows

	# Save container images to be included in release artifacts.
	docker save --output _output/release-$(GIT_VERSION)/images/calico-node.tar calico/node:$(GIT_VERSION)
	docker save --output _output/release-$(GIT_VERSION)/images/calico-typha.tar calico/typha:$(GIT_VERSION)
	docker save --output _output/release-$(GIT_VERSION)/images/calico-cni.tar calico/cni:$(GIT_VERSION)
	docker save --output _output/release-$(GIT_VERSION)/images/calico-kube-controllers.tar calico/kube-controllers:$(GIT_VERSION)
	docker save --output _output/release-$(GIT_VERSION)/images/calico-pod2daemon.tar calico/pod2daemon-flexvol:$(GIT_VERSION)
	docker save --output _output/release-$(GIT_VERSION)/images/calico-dikastes.tar calico/dikastes:$(GIT_VERSION)
	docker save --output _output/release-$(GIT_VERSION)/images/calico-flannel-migration-controller.tar calico/flannel-migration-controller:$(GIT_VERSION)

	# Collect release binaries from sub directories.
	cp -r cni-plugin/bin/github/ _output/release-$(GIT_VERSION)/binaries/cni
	cp -r felix/bin/ _output/release-$(GIT_VERSION)/binaries/felix
	cp -r calicoctl/bin/ _output/release-$(GIT_VERSION)/binaries/calicoctl

	# Produce tar files for release artifacts.
	tar -czvf release-$(GIT_VERSION).tgz -C _output release-$(GIT_VERSION)
	
	# Create a directory to upload to GitHub. Each file in this directory will be its own artifact on the release.
	rm -rf $(UPLOAD_DIR) && mkdir -p $(UPLOAD_DIR)
	cp node/dist/calico-windows-$(GIT_VERSION).zip $(UPLOAD_DIR)
	cp calico/bin/tigera-operator-$(GIT_VERSION)-$(HELM_CHART_RELEASE).tgz $(UPLOAD_DIR)
	cp _output/release-$(GIT_VERSION).tgz $(UPLOAD_DIR)

	# Push images to release registries.
	$(DRY_RUN) $(MAKE) -C pod2daemon push-images-to-registries push-manifests IMAGETAG=$(GIT_VERSION) RELEASE=true CONFIRM=true
	$(DRY_RUN) $(MAKE) -C calicoctl push-images-to-registries push-manifests IMAGETAG=$(GIT_VERSION) RELEASE=true CONFIRM=true
	$(DRY_RUN) $(MAKE) -C cni-plugin push-images-to-registries push-manifests IMAGETAG=$(GIT_VERSION) RELEASE=true CONFIRM=true
	$(DRY_RUN) $(MAKE) -C apiserver push-images-to-registries push-manifests IMAGETAG=$(GIT_VERSION) RELEASE=true CONFIRM=true
	$(DRY_RUN) $(MAKE) -C kube-controllers push-images-to-registries push-manifests IMAGETAG=$(GIT_VERSION) RELEASE=true CONFIRM=true
	$(DRY_RUN) $(MAKE) -C app-policy push-images-to-registries push-manifests IMAGETAG=$(GIT_VERSION) RELEASE=true CONFIRM=true
	$(DRY_RUN) $(MAKE) -C typha push-images-to-registries push-manifests IMAGETAG=$(GIT_VERSION) RELEASE=true CONFIRM=true
	$(DRY_RUN) $(MAKE) -C node push-images-to-registries push-manifests IMAGETAG=$(GIT_VERSION) RELEASE=true CONFIRM=true

	# Create the GitHub release, attaching the generated release binaries.
	$(DRY_RUN) ghr -u projectcalico -r calico -n $(GIT_VERSION) -b "$$RELEASE_BODY" $(GIT_VERSION) $(UPLOAD_DIR)
