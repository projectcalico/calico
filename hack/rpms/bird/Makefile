#################################################################################################
# Producer for the calico/bird image, which carries the patched BIRD RPM for
# node/Dockerfile and runs as a BGP router in tests. The tag is
# content-addressed: any change to the Dockerfile, spec file, patches, router
# files, or the version pins in metadata.mk produces a new tag, so the cache
# cannot be wrong by construction.
#################################################################################################

include ../../../metadata.mk

DEV_REGISTRIES ?= calico
ARCH          ?= $(shell go env GOARCH 2>/dev/null || echo amd64)
HOST_ARCH     := $(shell uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')

include image.mk

.PHONY: image print-tag print-image print-image-name

# Build (or rebuild) the per-arch image into the local docker daemon.
# Idempotent: if the image already exists locally with the expected tag, this is
# a no-op. CI uses this on cache miss; consumer Makefiles invoke it on demand.
#
# A host-arch build also gets the multi-arch name, so that a test can run the
# image by that name before CI has published it.
image:
	@if docker image inspect $(BIRD_IMAGE) >/dev/null 2>&1; then \
		echo "$(BIRD_IMAGE) already present locally, skipping build"; \
	else \
		docker buildx build \
			--platform linux/$(ARCH) \
			--build-arg BIRD_VER=$(BIRD_VER) \
			--build-arg BIRD_SHA256=$(BIRD_SHA256) \
			-t $(BIRD_IMAGE) \
			--load \
			.; \
	fi
ifeq ($(ARCH),$(HOST_ARCH))
	docker tag $(BIRD_IMAGE) $(BIRD_IMAGE_NAME)
endif

# Print the content-addressed tag (e.g. abcdef012345).
print-tag:
	@echo $(BIRD_IMAGE_TAG)

# Print the full image reference for the host arch.
print-image:
	@echo $(BIRD_IMAGE)

# Print the multi-arch image reference.
print-image-name:
	@echo $(BIRD_IMAGE_NAME)
