include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/cni-plugins

CNI_PLUGINS_IMAGE ?= third-party-cni-plugins
BUILD_IMAGES      ?= $(CNI_PLUGINS_IMAGE)

##############################################################################
# Include lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../../lib.Makefile

##############################################################################
# Upstream sources
##############################################################################
# The four plugins we copy from projectcalico/containernetworking-plugins.
# bandwidth is intentionally excluded — Calico has its own QoS support.
CN_FILES := host-local portmap loopback tuning

CONTAINERNETWORKING_PLUGINS_CLONED = .containernetworking-plugins-$(CNI_VERSION).cloned
FLANNEL_CNI_PLUGIN_CLONED          = .flannel-cni-plugin-$(FLANNEL_VERSION).cloned

# CNI_VERSION is a commit SHA (the fork has no release tag at the toolchain we
# build with), so clone then check it out rather than passing it to --branch.
$(CONTAINERNETWORKING_PLUGINS_CLONED):
	rm -rf containernetworking-plugins .containernetworking-plugins-*.cloned
	git clone https://github.com/projectcalico/containernetworking-plugins.git
	git -C containernetworking-plugins checkout $(CNI_VERSION)
	touch $@

$(FLANNEL_CNI_PLUGIN_CLONED):
	rm -rf flannel-cni-plugin .flannel-cni-plugin-*.cloned
	git clone --single-branch --branch $(FLANNEL_VERSION) https://github.com/projectcalico/flannel-cni-plugin.git
	touch $@

##############################################################################
# Plugin binaries (Linux only — Windows flannel is built in ../../cni-plugin)
##############################################################################
BIN = bin/$(ARCH)

CN_FLAGS = -ldflags "-X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=$(GIT_VERSION)"

# Pre-create the host-side module cache before docker mounts it. Without this,
# Docker creates the path as root if it doesn't exist, leaving user 1001 inside
# the container unable to write to /go/pkg/mod (e.g. fresh CI workers).
$(BIN)/host-local $(BIN)/loopback $(BIN)/portmap $(BIN)/tuning &: $(CONTAINERNETWORKING_PLUGINS_CLONED)
	mkdir -p $(GOMOD_CACHE)
	docker run \
		$(EXTRA_DOCKER_ARGS) \
		-v $(CURDIR)/containernetworking-plugins:/go/src/github.com/containernetworking/plugins:z \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) -w /go/src/github.com/containernetworking/plugins --rm $(CALICO_BUILD) \
		/bin/sh -xe -c 'GOFLAGS="-buildvcs=false" CGO_ENABLED=0 GOARCH=$(ARCH) ./build_linux.sh $(CN_FLAGS)'
	mkdir -p $(BIN)
	@$(foreach file,$(CN_FILES),cp containernetworking-plugins/bin/$(file) $(BIN)/$(file);)

$(BIN)/flannel: $(FLANNEL_CNI_PLUGIN_CLONED)
	mkdir -p $(GOMOD_CACHE)
	docker run \
		$(EXTRA_DOCKER_ARGS) \
		-v $(CURDIR)/flannel-cni-plugin:/go/src/github.com/flannel-io/cni-plugin:z \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) -w /go/src/github.com/flannel-io/cni-plugin --rm $(CALICO_BUILD) \
		/bin/sh -xe -c 'ARCH=$(ARCH) VERSION=$(FLANNEL_VERSION) make build_linux'
	mkdir -p $(BIN)
	cp flannel-cni-plugin/dist/flannel-$(ARCH) $(BIN)/flannel

##############################################################################
# Installer entrypoint (Calico-owned)
##############################################################################
# Small static Go binary used as the image entrypoint. Copies /plugins/ into
# the shared stage dir read by the install-cni init container. calico/base is
# distroless so a static binary is the right entrypoint here.
INSTALLER_SRCS = $(shell find cmd -name '*.go')

$(BIN)/install-cni-plugins: $(INSTALLER_SRCS)
	mkdir -p $(BIN)
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
		CGO_ENABLED=0 GOARCH=$(ARCH) go build -buildvcs=false -ldflags="-s -w" -o $@ ./cmd/install'

.PHONY: build
build: $(BIN)/host-local $(BIN)/portmap $(BIN)/loopback $(BIN)/tuning $(BIN)/flannel $(BIN)/install-cni-plugins

.PHONY: clean
clean:
	rm -f .containernetworking-plugins-*.cloned .flannel-cni-plugin-*.cloned .*.created* .*.published* .release.*
	rm -rf bin/ containernetworking-plugins/ flannel-cni-plugin/
	-docker image rm -f $$(docker images $(CNI_PLUGINS_IMAGE) -a -q) 2>/dev/null || true

##############################################################################
# Content-addressed image tag
#
# The plugin image rebuilds rarely — only when upstream pins move, the build
# toolchain changes, or this directory's files change. To avoid repetitive
# CI rebuilds we tag the image with a hash of its inputs and let CI probe the
# registry for a matching tag before building. See `image-content-addressed`.
##############################################################################
CNI_PLUGINS_HASH_INPUTS := \
	$(CNI_VERSION) \
	$(FLANNEL_VERSION) \
	$(GO_BUILD_VER) \
	$(CALICO_BASE_VER) \
	$(shell find Dockerfile Makefile cmd -type f | sort | xargs sha256sum | sha256sum | cut -d' ' -f1)
CNI_PLUGINS_HASH := $(shell echo "$(CNI_PLUGINS_HASH_INPUTS)" | sha256sum | cut -c1-12)

# The cache registry to probe for an existing content-addressed image. Defaults
# to the first dev registry. Override via CNI_PLUGINS_CACHE_REGISTRY if needed.
CNI_PLUGINS_CACHE_REGISTRY ?= $(firstword $(DEV_REGISTRIES))
CNI_PLUGINS_HASH_REF := $(CNI_PLUGINS_CACHE_REGISTRY)/$(CNI_PLUGINS_IMAGE):cache-$(CNI_PLUGINS_HASH)-$(ARCH)

##############################################################################
# Image build
##############################################################################
CNI_PLUGINS_IMAGE_CREATED = .cni-plugins.created-$(ARCH)

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: $(BUILD_IMAGES)

$(CNI_PLUGINS_IMAGE): $(CNI_PLUGINS_IMAGE_CREATED)
$(CNI_PLUGINS_IMAGE_CREATED): Dockerfile build | register
	$(DOCKER_BUILD) -t $(CNI_PLUGINS_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

# image-content-addressed probes the cache registry for the content-hash tag
# and either pulls + retags it (fast path) or falls through to a real build
# followed by a push of the hash tag (slow path, after a content change).
#
# The push tolerates failure so PR builds from contributors who can't write
# to the cache registry still pass; scheduled/master builds with credentials
# warm the cache for subsequent PRs.
#
# Used by CI; not typically run by developers.
.PHONY: image-content-addressed
image-content-addressed: $(REPO_ROOT)/bin/crane
	@echo "Probing for cached image $(CNI_PLUGINS_HASH_REF)"
	@if $(CRANE_CMD) manifest $(CNI_PLUGINS_HASH_REF) >/dev/null 2>&1; then \
		echo "Cache hit - pulling $(CNI_PLUGINS_HASH_REF)"; \
		docker pull $(CNI_PLUGINS_HASH_REF); \
		docker tag $(CNI_PLUGINS_HASH_REF) $(CNI_PLUGINS_IMAGE):latest-$(ARCH); \
		$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest; \
		touch $(CNI_PLUGINS_IMAGE_CREATED); \
	else \
		echo "Cache miss - building image"; \
		$(MAKE) image ARCH=$(ARCH); \
		docker tag $(CNI_PLUGINS_IMAGE):latest-$(ARCH) $(CNI_PLUGINS_HASH_REF); \
		docker push $(CNI_PLUGINS_HASH_REF) || echo "Cache push skipped (no registry credentials)"; \
	fi

.PHONY: print-cni-plugins-hash
print-cni-plugins-hash:
	@echo $(CNI_PLUGINS_HASH)

##############################################################################
# CI/CD
##############################################################################
.PHONY: ut
ut:
	$(DOCKER_GO_BUILD) go test ./cmd/...

# Probe the cache registry for a content-addressed image first; fall through to
# a real build (and push the cache tag) on cache miss. See image-content-addressed.
.PHONY: ci
ci: ut image-content-addressed

.PHONY: cd
cd: image-all cd-common

.PHONY: release-build
release-build: .release-$(VERSION).created
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries IMAGETAG=$(VERSION) RELEASE=true
	# Generate the `latest` images.
	$(MAKE) retag-build-images-with-registries IMAGETAG=latest RELEASE=true
	touch $@

release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@
