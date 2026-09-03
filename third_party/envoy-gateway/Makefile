include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/envoy-gateway

ENVOY_GATEWAY_IMAGE ?= envoy-gateway
BUILD_IMAGES ?= $(ENVOY_GATEWAY_IMAGE)

# For updating this version please see
# operator/docs/common_tasks.md, "Updating the bundled version of Envoy Gateway".
ENVOY_GATEWAY_VERSION=v1.8.2

##############################################################################
# Include lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../../lib.Makefile

##############################################################################
# Build
##############################################################################
ENVOY_GATEWAY_FETCHED=.envoy-gateway.fetched
ENVOY_GATEWAY_DOWNLOADED=.envoy-gateway.downloaded

DEP_PINS=dep-pins.txt
DEP_PATCH=dep-patches/0001-CVE-dependency-fixes.patch

# 	Patches live in two directories:
# 	  patches/     - functional changes to upstream source. Written and
# 	                 reviewed by hand; only ever verified to still apply.
# 	  dep-patches/ - dependency pins for CVE remediation, touching go.mod and
# 	                 go.sum only. Derived from $(DEP_PINS), so these are
# 	                 regenerated rather than edited.
# 	-F0 disables patch's default fuzz factor: a patch whose context no longer
# 	matches must fail rather than land somewhere approximate.
#
# 	The two are applied by separate targets so the generator can start from a
# 	tree carrying the functional patches but not the derived ones -- including
# 	when the checked-in derived patch no longer applies, which is exactly when
# 	it needs regenerating.

# 	Upstream at the pinned tag, with the functional patches applied. The tree is
# 	removed first so a re-extraction cannot leave files, or a generator
# 	baseline, behind from an older tag.
$(ENVOY_GATEWAY_FETCHED):
	rm -rf envoy-gateway && mkdir -p envoy-gateway
	curl -sSfL --retry 5 -o /tmp/envoy-gateway.tar.gz https://github.com/envoyproxy/gateway/archive/refs/tags/$(ENVOY_GATEWAY_VERSION).tar.gz
	tar xz --strip-components 1 -C envoy-gateway -f /tmp/envoy-gateway.tar.gz && rm -f /tmp/envoy-gateway.tar.gz
	for patch in patches/*.patch; do \
		if [ -f "$$patch" ]; then \
			patch -d envoy-gateway -p1 -F0 < "$$patch" || exit 1; \
		fi; \
	done
# 	Record what the generator diffs against, while the tree still holds
# 	upstream's go.mod and go.sum. No-op for a tree fetched with git clone.
	../../hack/thirdparty/init-dep-baseline.sh envoy-gateway
	touch $@

.PHONY: init-source
init-source: $(ENVOY_GATEWAY_DOWNLOADED)
$(ENVOY_GATEWAY_DOWNLOADED): $(ENVOY_GATEWAY_FETCHED)
# 	Reset the derived files to the baseline recorded at fetch time, so
# 	re-applying is idempotent across incremental builds.
	cd envoy-gateway && git checkout -- go.mod go.sum
	for patch in dep-patches/*.patch; do \
		if [ -f "$$patch" ]; then \
			patch -d envoy-gateway -p1 -F0 < "$$patch" || exit 1; \
		fi; \
	done
	touch $@

# 	Rebuild $(DEP_PATCH) from $(DEP_PINS). Runs in the pinned Go toolchain
# 	because go mod tidy's output depends on the Go version.
.PHONY: regen-dep-patches
regen-dep-patches: $(ENVOY_GATEWAY_FETCHED)
	$(DOCKER_GO_BUILD) ../../hack/thirdparty/regen-dep-patch.sh envoy-gateway $(DEP_PINS) $(DEP_PATCH)

# 	Fail if the checked-in patch is not what the pins produce.
.PHONY: check-dep-patches
check-dep-patches: regen-dep-patches
	@git diff --exit-code -- $(DEP_PATCH) || { \
		echo "ERROR: $(DEP_PATCH) is not what $(DEP_PINS) produces."; \
		echo "Run 'make -C third_party/envoy-gateway regen-dep-patches' and commit the result."; \
		exit 1; \
	}

.PHONY: build
build: bin/envoy-gateway-$(ARCH)

LD_FLAGS = \
	-X github.com/envoyproxy/gateway/internal/cmd/version.envoyGatewayVersion=$(ENVOY_GATEWAY_VERSION) \
	-X github.com/envoyproxy/gateway/internal/cmd/version.gitCommitID=$(GIT_COMMIT)

bin/envoy-gateway-$(ARCH): init-source
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			CGO_ENABLED=0 go build -C envoy-gateway -buildvcs=false -o ../$@ -v -tags=$(TAGS) -ldflags="$(LD_FLAGS) -s -w" github.com/envoyproxy/gateway/cmd/envoy-gateway'

.PHONY: clean
clean:
	rm -f .envoy-gateway.* .*.created* .*.published* .release.*
	rm -fr bin/ envoy-gateway/
	-docker image rm -f $$(docker images $(ENVOY_GATEWAY_IMAGE) -a -q)

##############################################################################
# Image
##############################################################################
ENVOY_GATEWAY_IMAGE_CREATED=.envoy-gateway.created-$(ARCH)

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

$(ENVOY_GATEWAY_IMAGE): $(ENVOY_GATEWAY_IMAGE_CREATED)
# register is order-only (|) so binfmt setup doesn't trigger unnecessary rebuilds.
$(ENVOY_GATEWAY_IMAGE_CREATED): Dockerfile build | register
	$(DOCKER_BUILD) -t $(ENVOY_GATEWAY_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

##############################################################################
# CI/CD
##############################################################################
ci: image

cd: image-all cd-common

.PHONY: release-build release-publish
release-build: .release-$(VERSION).created
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries IMAGETAG=$(VERSION) RELEASE=true
	# Generate the `latest` images.
	$(MAKE) retag-build-images-with-registries IMAGETAG=latest RELEASE=true
	touch $@

release-publish: release-prereqs bin/crane
	@if $(REPO_ROOT)/hack/image-published $(CRANE_CMD) "$(DEV_REGISTRIES)" "$(BUILD_IMAGES)" "$(VERSION)" "$(VALIDARCHES)"; then \
		echo "$(BUILD_IMAGES):$(VERSION) is already published, skipping"; \
	else \
		$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM); \
	fi
