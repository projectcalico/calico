# Shared definition of the calico/bird image reference. Included by the
# producer Makefile in this directory and by node/Makefile and confd/Makefile so
# they all agree on the tag without invoking a sub-make.
#
# Includers must already have BIRD_VERSION, ARCH, and DEV_REGISTRIES defined
# (the consumer Makefiles get these from metadata.mk and lib.Makefile).

# Per-arch tag used for the local build and as the FROM base in node/Dockerfile.
BIRD_IMAGE ?= $(firstword $(DEV_REGISTRIES))/bird:$(BIRD_VERSION)-$(ARCH)
