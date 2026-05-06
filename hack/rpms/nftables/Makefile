#################################################################################################
# Producer for the calico/nftables-rpms image consumed by node/Dockerfile and
# istio/Dockerfile-install-cni. The tag is content-addressed: any change to the
# spec files, patches, or the version pins in metadata.mk produces a new tag,
# so the cache cannot be wrong by construction.
#################################################################################################

include ../../../metadata.mk

DEV_REGISTRIES ?= calico
ARCH          ?= $(shell go env GOARCH 2>/dev/null || echo amd64)

# Content-addressed tag. Hashes the spec files, patches, and the four
# nftables/libnftnl version pins from metadata.mk. Take the first 12 hex chars
# so the tag stays human-scannable.
NFT_RPMS_TAG := $(shell ( \
		cat libnftnl.spec nftables.spec patches/*.patch && \
		echo $(NFTABLES_VER) $(NFTABLES_SHA256) $(LIBNFTNL_VER) $(LIBNFTNL_SHA256) \
	) | sha256sum | cut -c1-12)

NFT_RPMS_IMAGE := $(firstword $(DEV_REGISTRIES))/nftables-rpms:$(NFT_RPMS_TAG)-$(ARCH)

.PHONY: image print-tag print-image

# Build (or rebuild) the per-arch RPM producer image into the local docker daemon.
# Idempotent: if the image already exists locally with the expected tag, this is
# a no-op. CI uses this on cache miss; consumer Makefiles invoke it on demand.
image:
	@if docker image inspect $(NFT_RPMS_IMAGE) >/dev/null 2>&1; then \
		echo "$(NFT_RPMS_IMAGE) already present locally, skipping build"; \
	else \
		docker buildx build \
			--platform linux/$(ARCH) \
			--build-arg NFTABLES_VER=$(NFTABLES_VER) \
			--build-arg NFTABLES_SHA256=$(NFTABLES_SHA256) \
			--build-arg LIBNFTNL_VER=$(LIBNFTNL_VER) \
			--build-arg LIBNFTNL_SHA256=$(LIBNFTNL_SHA256) \
			-t $(NFT_RPMS_IMAGE) \
			--load \
			.; \
	fi

# Print the content-addressed tag (e.g. abcdef012345). Consumers use this to
# pass NFT_RPMS_IMAGE through as a build arg.
print-tag:
	@echo $(NFT_RPMS_TAG)

# Print the full image reference for the host arch.
print-image:
	@echo $(NFT_RPMS_IMAGE)
