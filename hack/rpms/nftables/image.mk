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

# Content-addressed tag. Hashes the producer Dockerfile (whose base image
# determines the dist tag and glibc requirements of the resulting RPMs), the
# spec files, patches, and the four nftables/libnftnl version pins from
# metadata.mk. First 12 hex chars so the tag stays human-scannable.
NFT_RPMS_TAG := $(shell ( \
		cat $(NFT_RPMS_DIR)Dockerfile $(NFT_RPMS_DIR)libnftnl.spec $(NFT_RPMS_DIR)nftables.spec $(NFT_RPMS_DIR)patches/*.patch && \
		echo $(NFTABLES_VER) $(NFTABLES_SHA256) $(LIBNFTNL_VER) $(LIBNFTNL_SHA256) \
	) | sha256sum | cut -c1-12)

NFT_RPMS_IMAGE ?= $(firstword $(DEV_REGISTRIES))/nftables-rpms:$(NFT_RPMS_TAG)-$(ARCH)

# The image's /rpms and /src as a directory, which consumers pass as their
# nft-rpms build context. A directory travels with the build to any builder;
# an image only in the local daemon is invisible to the docker-container
# builder that the remote layer cache needs. Consumers add a rule:
#
#   $(NFT_RPMS_CONTEXT): | nft-rpms-image
#   	$(NFT_RPMS_EXPORT_CONTEXT)
NFT_RPMS_CONTEXT = $(NFT_RPMS_DIR)context-$(NFT_RPMS_TAG)-$(ARCH)

define NFT_RPMS_EXPORT_CONTEXT
rm -rf $@.tmp && mkdir -p $@.tmp
ctr=$$(docker create --platform linux/$(ARCH) $(NFT_RPMS_IMAGE)) && \
	{ docker cp $$ctr:/rpms $@.tmp/rpms && docker cp $$ctr:/src $@.tmp/src; rc=$$?; \
	  docker rm -f $$ctr >/dev/null; exit $$rc; }
mv $@.tmp $@
endef
