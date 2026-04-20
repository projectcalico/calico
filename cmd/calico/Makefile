include ../../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/cmd/calico

CALICO_IMAGE ?= calico
BUILD_IMAGES ?= $(CALICO_IMAGE)

include ../../lib.Makefile

# Paths within the build container for BPF source (needed for the CGO
# build-cgo target, which produces the binary embedded in the node image).
LIBBPF_CONTAINER_PATH = /go/src/github.com/projectcalico/calico/felix/bpf-gpl/libbpf/src/
BPFGPL_CONTAINER_PATH = /go/src/github.com/projectcalico/calico/felix/bpf-gpl/
LIBBPF_A = $(REPO_ROOT)/felix/bpf-gpl/libbpf/src/$(ARCH)/libbpf.a

ifeq ($(ARCH), $(filter $(ARCH),amd64 arm64))
# When cross-compiling, force lld as the linker — GNU ld is single-target,
# while lld natively links the cross-arch ELF objects produced by clang.
# (The cross sysroot itself is already supplied via CC's --sysroot flag.)
CROSS_CGO_LDFLAGS=
ifneq ($(CROSS_SYSROOT),)
	CROSS_CGO_LDFLAGS=$(CROSS_LDFLAGS)
endif
CGO_LDFLAGS = "-L$(LIBBPF_CONTAINER_PATH)/$(ARCH) $(CROSS_CGO_LDFLAGS) -lbpf -lelf -lz"
CGO_CFLAGS = "-I$(LIBBPF_CONTAINER_PATH) -I$(BPFGPL_CONTAINER_PATH)"
endif

FIPS ?= false
ifeq ($(FIPS),true)
BINDIR = bin/$(ARCH)-fips
CONTAINER_MARKER = .image.created-$(ARCH)-fips
IMAGE_TAG = latest-fips
CACHE_TAG = $(ARCH)-fips
else
BINDIR = bin
CONTAINER_MARKER = .image.created-$(ARCH)
IMAGE_TAG = latest
CACHE_TAG = $(ARCH)
endif

# BuildKit registry cache for the calico image. One cache tag per
# arch/FIPS variant so concurrent variant builds don't stomp on each
# other's cache. Branch builds set STORE_BUILD_CACHE=true to push cache
# back with mode=max; PR and local dev builds read-only from the cache.
BUILDCACHE_REGISTRY ?= gcr.io/unique-caldron-775/buildcache/calico/calico
BUILDX_BUILDER ?= calico-buildx
BUILDX_CACHE_FROM = --cache-from=type=registry,ref=$(BUILDCACHE_REGISTRY):$(CACHE_TAG)
ifeq ($(STORE_BUILD_CACHE),true)
BUILDX_CACHE_TO = --cache-to=type=registry,ref=$(BUILDCACHE_REGISTRY):$(CACHE_TAG),mode=max
else
BUILDX_CACHE_TO =
endif

.PHONY: clean
clean:
	rm -rf bin .image.created-*
	-docker image rm -f $$(docker images $(CALICO_IMAGE) -a -q) 2>/dev/null

.PHONY: ut
ut:
	$(DOCKER_GO_BUILD) sh -c "CGO_ENABLED=0 go test -cover -count=1 ."

# build-cgo produces a CGO+libbpf binary consumed by the node image. The
# calico/calico image itself no longer goes through this target — its
# binary is compiled inside the Dockerfile by `make image`.
.PHONY: build-cgo
build-cgo: $(BINDIR)/calico-cgo-$(ARCH)

$(BINDIR)/calico-cgo-$(ARCH): $(LIBBPF_A)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./, $@)
else ifeq ($(ARCH),$(filter $(ARCH),amd64 arm64))
	$(call build_cgo_binary, ./, $@)
else
	$(call build_binary, ./, $@)
endif

$(LIBBPF_A):
	$(MAKE) -C $(REPO_ROOT)/felix libbpf ARCH=$(ARCH)

REGISTRAR_BIN = $(REPO_ROOT)/pod2daemon/bin/node-driver-registrar-$(ARCH)
$(REGISTRAR_BIN):
	$(MAKE) -C $(REPO_ROOT)/pod2daemon bin/node-driver-registrar-$(ARCH)

# buildx-setup ensures a docker-container driver builder exists. The default
# docker driver doesn't support registry cache export, so we need this for
# cache-to to work. Idempotent: a no-op if the builder already exists.
.PHONY: buildx-setup
buildx-setup:
	@if ! docker buildx inspect $(BUILDX_BUILDER) >/dev/null 2>&1; then \
		docker buildx create --name $(BUILDX_BUILDER) --driver docker-container; \
	fi

.PHONY: image image-all
image: $(CONTAINER_MARKER)

$(CONTAINER_MARKER): $(REPO_ROOT)/docker/calico/Dockerfile $(REGISTRAR_BIN) buildx-setup
	docker buildx build \
		--builder $(BUILDX_BUILDER) \
		--load \
		--platform=linux/$(ARCH) \
		$(BUILDX_CACHE_FROM) $(BUILDX_CACHE_TO) \
		--build-arg CALICO_BASE=$(CALICO_BASE) \
		--build-arg UBI_IMAGE=$(UBI_IMAGE) \
		--build-arg GO_BUILD_IMAGE=$(GO_BUILD_IMAGE) \
		--build-arg GO_BUILD_VER=$(GO_BUILD_VER) \
		--build-arg TARGETARCH=$(ARCH) \
		--build-arg FIPS=$(FIPS) \
		--build-arg GIT_VERSION=$(GIT_VERSION) \
		--build-arg GIT_DESCRIPTION=$(GIT_DESCRIPTION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(DATE) \
		--build-arg BUILD_ID=$(BUILD_ID) \
		-t $(CALICO_IMAGE):$(IMAGE_TAG)-$(ARCH) \
		-f $(REPO_ROOT)/docker/calico/Dockerfile \
		$(REPO_ROOT)
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=$(IMAGE_TAG) LATEST_IMAGE_TAG=$(IMAGE_TAG)
	touch $@

image-all: $(addprefix sub-image-,$(VALIDARCHES)) sub-image-fips-amd64
sub-image-%:
	$(MAKE) image ARCH=$*
sub-image-fips-%:
	$(MAKE) image FIPS=true ARCH=$*
