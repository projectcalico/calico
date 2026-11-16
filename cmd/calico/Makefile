include ../../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/cmd/calico

CALICO_IMAGE ?= calico
BUILD_IMAGES ?= $(CALICO_IMAGE)

include ../../lib.Makefile

# Source files for the combined binary, derived from cmd/deps.txt.
SRC_FILES := $(call local-deps-go-files,cmd)

# Paths within the build container for BPF source (needed for CGO builds).
LIBBPF_CONTAINER_PATH = $(BUILD_REPO_ROOT)/felix/bpf-gpl/libbpf/src/
BPFGPL_CONTAINER_PATH = $(BUILD_REPO_ROOT)/felix/bpf-gpl/
LIBBPF_A = $(REPO_ROOT)/felix/bpf-gpl/libbpf/src/$(ARCH)/libbpf.a

# When cross-compiling, force lld as the linker — GNU ld is single-target,
# while lld natively links the cross-arch ELF objects produced by clang.
# (The cross sysroot itself is already supplied via CC's --sysroot flag.)
CROSS_CGO_LDFLAGS=
ifneq ($(CROSS_SYSROOT),)
	CROSS_CGO_LDFLAGS=$(CROSS_LDFLAGS)
endif
# Normalize userspace types to ensure consistency across architectures.
# On ppc64le the kernel UAPI defines __u64 as `unsigned long` unless
# __SANE_USERSPACE_TYPES__ is set, which makes cgo reject `C.ulonglong`
# arguments to __u64 parameters (felix/bpf/maps/syscall.go). Matches the
# same flag in felix/Makefile and node/Makefile.
ARCH_CGO_CFLAGS=
ifeq ($(ARCH),ppc64le)
	ARCH_CGO_CFLAGS=-D__SANE_USERSPACE_TYPES__
endif
CGO_LDFLAGS = "-L$(LIBBPF_CONTAINER_PATH)/$(ARCH) $(CROSS_CGO_LDFLAGS) -lbpf -lelf -lz"
CGO_CFLAGS = "-I$(LIBBPF_CONTAINER_PATH) -I$(BPFGPL_CONTAINER_PATH) $(ARCH_CGO_CFLAGS)"

BINDIR = bin
CONTAINER_MARKER = .image.created-$(ARCH)
IMAGE_TAG = latest

.PHONY: clean
clean:
	rm -rf bin .image.created-* .release-*
	-docker image rm -f $$(docker images $(CALICO_IMAGE) -a -q) 2>/dev/null

.PHONY: ut
ut:
	$(DOCKER_GO_BUILD) sh -c "CGO_ENABLED=0 go test -cover -count=1 ."

.PHONY: build build-cgo build-race
build: $(BINDIR)/calico-$(ARCH)
build-cgo: $(BINDIR)/calico-cgo-$(ARCH)
build-race: $(BINDIR)/calico-race-$(ARCH)

$(BINDIR)/calico-$(ARCH): $(SRC_FILES)
	$(call build_binary, ./, $@)

$(BINDIR)/calico-cgo-$(ARCH): $(LIBBPF_A) $(SRC_FILES)
	$(call build_cgo_binary, ./, $@)

# Race-enabled combined binary for Felix FV runs. The race detector requires
# CGO so we always build with CGO_ENABLED=1 and pull in libbpf the same way
# the cgo variant does.
ifeq ($(NATIVE_GO_BUILD),true)
RACE_BUILD_RUN = env CGO_ENABLED=1 $(if $(CROSS_CC),CC="$(CROSS_CC)") CGO_CFLAGS=$(CGO_CFLAGS) CGO_LDFLAGS=$(CGO_LDFLAGS)
else
RACE_BUILD_RUN = $(DOCKER_RUN) \
	-e CGO_ENABLED=1 \
	$(if $(CROSS_CC),-e CC="$(CROSS_CC)") \
	-e CGO_CFLAGS=$(CGO_CFLAGS) \
	-e CGO_LDFLAGS=$(CGO_LDFLAGS) \
	$(CALICO_BUILD)
endif

$(BINDIR)/calico-race-$(ARCH): $(LIBBPF_A) $(SRC_FILES)
	mkdir -p $(BINDIR)
	$(RACE_BUILD_RUN) sh -c '$(GIT_CONFIG_SSH) go build -race -o $@ -v -buildvcs=false -ldflags "$(LDFLAGS)" ./'

$(BINDIR)/LICENSE: $(REPO_ROOT)/LICENSE.md
	mkdir -p $(BINDIR)
	cp $(REPO_ROOT)/LICENSE.md $@

REGISTRAR_BIN = $(REPO_ROOT)/pod2daemon/bin/node-driver-registrar-$(ARCH)
$(REGISTRAR_BIN):
	$(MAKE) -C $(REPO_ROOT)/pod2daemon bin/node-driver-registrar-$(ARCH)

# Everything docker/calico/Dockerfile reads, at the paths it reads them from, with
# the build args baked in as defaults. A builder given only this directory, such as
# CI's rootless buildkit with no checkout or Makefile, produces the same image as
# `make image`.
IMAGE_CONTEXT = $(BINDIR)/image-context-$(ARCH)

.PHONY: image-context
image-context: $(IMAGE_CONTEXT)/Dockerfile

$(IMAGE_CONTEXT)/Dockerfile: $(REPO_ROOT)/docker/calico/Dockerfile $(REPO_ROOT)/docker/calico/typha.cfg $(BINDIR)/calico-$(ARCH) $(BINDIR)/LICENSE $(REGISTRAR_BIN)
	rm -rf $(IMAGE_CONTEXT)
	mkdir -p $(IMAGE_CONTEXT)/cmd/calico/$(BINDIR) $(IMAGE_CONTEXT)/pod2daemon/bin $(IMAGE_CONTEXT)/docker/calico
	cp $(BINDIR)/calico-$(ARCH) $(BINDIR)/LICENSE $(IMAGE_CONTEXT)/cmd/calico/$(BINDIR)/
	cp $(REGISTRAR_BIN) $(IMAGE_CONTEXT)/pod2daemon/bin/
	cp $(REPO_ROOT)/docker/calico/typha.cfg $(IMAGE_CONTEXT)/docker/calico/
	# A global ARG with a default is what a stage's bare `ARG X` inherits.
	sed -e '1i ARG BIN_DIR=cmd/calico/$(BINDIR)' \
		-e '1i ARG GIT_VERSION=$(GIT_VERSION)' \
		-e 's|^ARG CALICO_BASE$$|ARG CALICO_BASE=$(CALICO_BASE)|' \
		-e 's|^ARG UBI_IMAGE$$|ARG UBI_IMAGE=$(UBI_IMAGE)|' \
		$(REPO_ROOT)/docker/calico/Dockerfile > $(IMAGE_CONTEXT)/Dockerfile

.PHONY: image image-all
image: $(CONTAINER_MARKER)

$(CONTAINER_MARKER): $(IMAGE_CONTEXT)/Dockerfile | register
	$(DOCKER_BUILD) --build-arg TARGETARCH=$(ARCH) -t $(CALICO_IMAGE):$(IMAGE_TAG)-$(ARCH) $(IMAGE_CONTEXT)
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=$(IMAGE_TAG) LATEST_IMAGE_TAG=$(IMAGE_TAG)
	touch $@

image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

###############################################################################
# CI/CD
###############################################################################
## Deploys images to registry
.PHONY: cd
cd: image-all cd-common

###############################################################################
# Release
###############################################################################
## Produces the combined calico image at the specified version. Clean first for a fresh build.
.PHONY: release-build release-publish
release-build: .release-$(VERSION).created
.release-$(VERSION).created:
	$(MAKE) image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=latest
	touch $@

## Pushes the combined calico image to the registries.
.PHONY: release-publish
release-publish: release-prereqs bin/crane
	@if $(REPO_ROOT)/hack/image-published $(CRANE_CMD) "$(DEV_REGISTRIES)" "$(BUILD_IMAGES)" "$(VERSION)" "$(VALIDARCHES)"; then \
		echo "$(BUILD_IMAGES):$(VERSION) is already published, skipping"; \
	else \
		$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM); \
	fi
