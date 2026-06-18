include ../../metadata.mk

PACKAGE_NAME ?= github.com/projectcalico/calico/third_party/envoy-ratelimit

ENVOY_RATELIMIT_IMAGE ?= envoy-ratelimit
BUILD_IMAGES ?= $(ENVOY_RATELIMIT_IMAGE)

# For updating this version please see
# https://github.com/tigera/operator/blob/master/docs/common_tasks.md#updating-the-bundled-version-of-envoy-gateway
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
ENVOY_RATELIMIT_DOWNLOADED=.envoy-ratelimit.downloaded

.PHONY: init-source
init-source: $(ENVOY_RATELIMIT_DOWNLOADED)
$(ENVOY_RATELIMIT_DOWNLOADED):
	git clone -n https://github.com/envoyproxy/ratelimit.git envoy-ratelimit
	cd envoy-ratelimit && git checkout $(ENVOY_RATELIMIT_VERSION)
# 	Apply patches for the specified Envoy Ratelimit version if patches directory exists.
# 	This code checks for the presence of a patches directory corresponding to ENVOY_RATELIMIT_VERSION.
# 	If the directory exists, it iterates over all .patch files within it.
# 	For each valid patch file, it applies the patch to the envoy-ratelimit directory using patch -p1.
	for patch in patches/*.patch; do \
		if [ -f "$$patch" ]; then \
			patch -d envoy-ratelimit -p1 < "$$patch"; \
		fi; \
	done; \
	touch $@

.PHONY: build
build: bin/envoy-ratelimit-$(ARCH)

# Upstream ratelimit ff287602 (the ref pinned by the Envoy Gateway v1.8.0 helm
# chart) requires Go >= 1.26.2 in its go.mod `go` directive. release-v3.32 still
# pins GO_VERSION=1.25.x for the rest of the tree, so we need GOTOOLCHAIN here to
# let Go auto-download a newer toolchain inside the build container.
#
# Pin minimum 1.26.4 (not bare `auto`) because plain `auto` resolves to the
# go.mod directive's exact 1.26.2, which still ships these 5 stdlib HIGHs:
#   CVE-2026-33811  LookupCNAME cgo DoS
#   CVE-2026-33814  HTTP/2 SETTINGS infinite loop
#   CVE-2026-39820  net/mail consumeComment DoS
#   CVE-2026-39836  Dial / LookupPort NUL byte handling
#   CVE-2026-42499  net/mail consumePhrase DoS
# All five are fixed in Go 1.26.3. The `+auto` suffix lets a future go.mod
# directive higher than 1.26.4 still win without re-editing this line.
#
# Remove this override once release-v3.32 picks up GO_VERSION >= 1.26.4.
bin/envoy-ratelimit-$(ARCH): init-source
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			CGO_ENABLED=0 GOTOOLCHAIN=go1.26.4+auto go build -C envoy-ratelimit -buildvcs=false -o ../$@ -v -tags=$(TAGS) -ldflags="$(LD_FLAGS) -s -w" github.com/envoyproxy/ratelimit/src/service_cmd'

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
