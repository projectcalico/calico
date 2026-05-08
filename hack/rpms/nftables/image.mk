# Shared definition of the calico/nftables-rpms image reference. Included by
# the producer Makefile in this directory and by node/Makefile and
# istio/Makefile so they all agree on the tag without having to invoke a
# sub-make (which is fragile under deeply nested e2e/kind builds, where the
# parent's MAKEFLAGS leak --print-directory into $(shell $(MAKE) ...) output
# and corrupt the captured value).
#
# Includers must already have NFTABLES_VER, NFTABLES_SHA256, LIBNFTNL_VER,
# LIBNFTNL_SHA256, ARCH, and DEV_REGISTRIES defined (the consumer Makefiles
# get these from metadata.mk and lib.Makefile).

NFT_RPMS_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

# Content-addressed tag. Hashes the spec files, patches, and the four
# nftables/libnftnl version pins from metadata.mk. First 12 hex chars so the
# tag stays human-scannable.
NFT_RPMS_TAG := $(shell ( \
		cat $(NFT_RPMS_DIR)libnftnl.spec $(NFT_RPMS_DIR)nftables.spec $(NFT_RPMS_DIR)patches/*.patch && \
		echo $(NFTABLES_VER) $(NFTABLES_SHA256) $(LIBNFTNL_VER) $(LIBNFTNL_SHA256) \
	) | sha256sum | cut -c1-12)

NFT_RPMS_IMAGE ?= $(firstword $(DEV_REGISTRIES))/nftables-rpms:$(NFT_RPMS_TAG)-$(ARCH)
