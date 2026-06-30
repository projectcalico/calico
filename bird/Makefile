#################################################################################################
# Producer for the calico/bird image: upstream BIRD built from the official
# release tarball, consumed by node/Dockerfile (FROM ${BIRD_IMAGE}) and used as a
# runnable BGP test peer by the e2e / k8st / kubevirt suites.
#################################################################################################

include ../metadata.mk

DEV_REGISTRIES ?= calico
ARCH          ?= $(shell go env GOARCH 2>/dev/null || echo amd64)

include image.mk

# Plain (arch-less) tag used as a runnable BGP test peer by the e2e/k8st/kubevirt
# suites and by confd's BIRD config validation. Built as an alias of the per-arch
# image for the host architecture.
BIRD_IMAGE_PLAIN ?= $(firstword $(DEV_REGISTRIES))/bird:$(BIRD_VERSION)

.PHONY: image image-all print-image

# Build (or rebuild) the per-arch BIRD image into the local docker daemon.
# Idempotent: if the image already exists locally with the expected tag, this is
# a no-op. CI uses this on cache miss; consumer Makefiles invoke it on demand.
image:
	@if docker image inspect $(BIRD_IMAGE) >/dev/null 2>&1; then \
		echo "$(BIRD_IMAGE) already present locally, skipping build"; \
	else \
		docker buildx build \
			--platform linux/$(ARCH) \
			--build-arg BIRD_VERSION=$(BIRD_VERSION) \
			--build-arg BIRD_SHA256=$(BIRD_SHA256) \
			-t $(BIRD_IMAGE) \
			--load \
			.; \
	fi
	docker tag $(BIRD_IMAGE) $(BIRD_IMAGE_PLAIN)

image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

print-image:
	@echo $(BIRD_IMAGE)
