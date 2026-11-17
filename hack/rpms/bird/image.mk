# Shared definition of the calico/bird image reference. Included by the
# producer Makefile in this directory and by the Makefiles that consume the
# image, so they all agree on the tag without invoking a sub-make.
#
# Includers must already have BIRD_VER, BIRD_SHA256, ARCH, and DEV_REGISTRIES
# defined (the consumer Makefiles get these from metadata.mk and lib.Makefile).

BIRD_IMAGE_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

# Content-addressed tag. Hashes the Dockerfile (whose base image determines
# the dist tag and glibc requirements of the resulting RPM), the spec file,
# patches, router files, and the BIRD version pins from metadata.mk. First 12
# hex chars so the tag stays human-scannable.
#
# LC_ALL=C because a glob's order follows the locale, and the tag must be the
# same on every machine.
BIRD_IMAGE_TAG := $(shell ( \
		export LC_ALL=C && \
		cat $(BIRD_IMAGE_DIR)Dockerfile $(BIRD_IMAGE_DIR)bird.spec $(BIRD_IMAGE_DIR)patches/*.patch $(BIRD_IMAGE_DIR)router/* && \
		echo $(BIRD_VER) $(BIRD_SHA256) \
	) | sha256sum | cut -c1-12)

# The multi-arch name, and the per-arch image behind it.
BIRD_IMAGE_NAME ?= $(firstword $(DEV_REGISTRIES))/bird:$(BIRD_IMAGE_TAG)
BIRD_IMAGE ?= $(BIRD_IMAGE_NAME)-$(ARCH)
