include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/envoy-ratelimit

ENVOY_RATELIMIT_IMAGE ?= envoy-ratelimit
BUILD_IMAGES ?= $(ENVOY_RATELIMIT_IMAGE)

# For updating this version please see
# operator/docs/common_tasks.md, "Updating the bundled version of Envoy Gateway".
ENVOY_RATELIMIT_VERSION=ff287602

##############################################################################
# Include lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../../lib.Makefile

##############################################################################
# Build
##############################################################################
ENVOY_RATELIMIT_FETCHED=.envoy-ratelimit.fetched
ENVOY_RATELIMIT_DOWNLOADED=.envoy-ratelimit.downloaded

DEP_PINS=dep-pins.txt

# 	patches/ holds one directory per class, applied in name order:
# 	  01-custom-patches/   - hand-written; only ever verified to still apply.
# 	  02-auto-gen-patches/ - derived from $(DEP_PINS); regenerated as a whole
# 	                         directory, not edited.
#
# 	Order matters: the baseline is taken after 01, so 02 is a delta on top of
# 	it. They are applied by separate targets so the generator can start from a
# 	tree with 01 but not 02 -- the state it needs when 02 no longer applies.
# 	-F0 drops patch's default fuzz: a stale patch fails rather than landing
# 	somewhere approximate.

# 	Upstream at the pinned ref with class 01 applied -- there is none today,
# 	so 01-custom-patches/ does not exist and the -f guard skips it.
$(ENVOY_RATELIMIT_FETCHED):
	git clone -n https://github.com/envoyproxy/ratelimit.git envoy-ratelimit
	cd envoy-ratelimit && git checkout $(ENVOY_RATELIMIT_VERSION)
	for patch in patches/01-custom-patches/*.patch; do \
		if [ -f "$$patch" ]; then \
			patch -d envoy-ratelimit -p1 -F0 < "$$patch" || exit 1; \
		fi; \
	done
# 	Record what the generator diffs against, before any dependency patch
# 	lands. No-op for a cloned tree.
	../../hack/thirdparty/init-dep-baseline.sh envoy-ratelimit
	touch $@

.PHONY: init-source
init-source: $(ENVOY_RATELIMIT_DOWNLOADED)
$(ENVOY_RATELIMIT_DOWNLOADED): $(ENVOY_RATELIMIT_FETCHED)
# 	Reset to the pinned ref so re-applying is idempotent.
	cd envoy-ratelimit && git checkout -- go.mod go.sum
	for patch in patches/02-auto-gen-patches/*.patch; do \
		if [ -f "$$patch" ]; then \
			patch -d envoy-ratelimit -p1 -F0 < "$$patch" || exit 1; \
		fi; \
	done
	touch $@

# 	Rebuild patches/02-auto-gen-patches/ from $(DEP_PINS), in the pinned Go toolchain --
# 	go mod tidy's output depends on the Go version.
.PHONY: regen-dep-patches
regen-dep-patches: $(ENVOY_RATELIMIT_FETCHED)
	$(DOCKER_GO_BUILD) ../../hack/thirdparty/regen-dep-patch.sh envoy-ratelimit $(DEP_PINS) patches/02-auto-gen-patches/0001-cve-dependency-fixes.patch

# 	Fail if the checked-in patch is not what the pins produce.
.PHONY: check-dep-patches
check-dep-patches: regen-dep-patches
	@git diff --exit-code -- patches/02-auto-gen-patches || { \
		echo "ERROR: patches/02-auto-gen-patches/ is not what $(DEP_PINS) produces."; \
		echo "Run 'make -C third_party/envoy-ratelimit regen-dep-patches' and commit the result."; \
		exit 1; \
	}

.PHONY: build
build: bin/envoy-ratelimit-$(ARCH)

bin/envoy-ratelimit-$(ARCH): init-source
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			CGO_ENABLED=0 go build -C envoy-ratelimit -buildvcs=false -o ../$@ -v -tags=$(TAGS) -ldflags="$(LD_FLAGS) -s -w" github.com/envoyproxy/ratelimit/src/service_cmd'

.PHONY: clean
clean:
	rm -f .envoy-ratelimit.* .*.created* .*.published* .release.*
	rm -fr bin/ envoy-ratelimit/
	-docker image rm -f $$(docker images $(ENVOY_RATELIMIT_IMAGE) -a -q)

##############################################################################
# Image
##############################################################################
ENVOY_RATELIMIT_IMAGE_CREATED=.envoy-ratelimit.created-$(ARCH)

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

$(ENVOY_RATELIMIT_IMAGE): $(ENVOY_RATELIMIT_IMAGE_CREATED)
$(ENVOY_RATELIMIT_IMAGE_CREATED): Dockerfile build
	$(DOCKER_BUILD) -t $(ENVOY_RATELIMIT_IMAGE):latest-$(ARCH) -f Dockerfile .
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
