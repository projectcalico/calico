include ../../../metadata.mk

PACKAGE_NAME=github.com/projectcalico/calico/e2e/images/rapidclient

include ../../../lib.Makefile

QUAY_REGISTRY ?= quay.io/tigeradev
TAG_NAME ?= $(shell git branch --show-current)

# Architectures the published manifest list must cover. arm64 is required: the
# packet-size server runs on arm64 clusters (e.g. azr-aks ARM), and an amd64-only
# image is exactly the bug this image replaces. Assigned with := (not ?=) because
# lib.Makefile, included above, already sets ARCHES to its four-arch default, so
# ?= would be a no-op and publish would build ppc64le/s390x too. Still overridable
# on the command line.
ARCHES := amd64 arm64

IMAGE = $(QUAY_REGISTRY)/rapidclient

.PHONY: build image publish clean ut fv st ci

build: bin/rapidclient-$(ARCH)

# Per-arch static binary. CGO is disabled so cross-compilation (via GOARCH) is
# clean and the result runs on FROM scratch. Exclude _test.go so editing a test
# doesn't force a binary rebuild.
bin/rapidclient-%: $(filter-out %_test.go,$(wildcard *.go))
	mkdir -p bin
	$(DOCKER_RUN) -e CGO_ENABLED=0 -e GOARCH=$* $(CALICO_BUILD) \
		go build -o $@ -ldflags "-s -w" .

# ut is the repo-wide unit-test convention; lib.Makefile's `test: ut fv st`
# aggregates it. This image has no fv/st layer, so those are no-ops (defining them
# is what makes `make test` work rather than erroring on a missing `ut`/`fv`/`st`).
ut:
	$(DOCKER_RUN) $(CALICO_BUILD) go test ./...

fv st:
	@:

# ci is the CI entrypoint (see .semaphore/.../20-e2e-images.yml).
ci: ut

# image builds a local, single-arch image for development (buildx --load cannot
# load a multi-platform build). TARGETARCH drives the Dockerfile's binary COPY.
image: bin/rapidclient-$(ARCH)
	docker buildx build --load --platform=linux/$(ARCH) --pull \
		-f Dockerfile -t $(IMAGE):$(TAG_NAME) .

# publish builds all architectures into a single manifest list and pushes it.
publish: $(addprefix bin/rapidclient-,$(ARCHES))
	docker buildx build --platform=$(shell echo $(ARCHES) | sed 's/ /,/g; s,[^,]*,linux/&,g') \
		--push --pull -f Dockerfile -t $(IMAGE):$(TAG_NAME) .
	# Guard against silently regressing to a single-arch image (the original bug):
	# the published tag must be a manifest list covering every arch in ARCHES.
	@for a in $(ARCHES); do \
		docker buildx imagetools inspect $(IMAGE):$(TAG_NAME) | grep -q "linux/$$a" \
			|| { echo "ERROR: $(IMAGE):$(TAG_NAME) missing linux/$$a"; exit 1; }; \
	done
	@if [ "$(TAG_NAME)" = "master" ]; then \
		docker buildx imagetools create -t $(IMAGE):latest $(IMAGE):$(TAG_NAME); \
		echo "Pushed $(IMAGE):latest"; \
	fi

clean:
	rm -rf bin/
