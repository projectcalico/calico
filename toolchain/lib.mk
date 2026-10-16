# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Builds and checks one toolchain image. An image's Makefile sets these, then
# includes this file:
#
#   IMAGE       the repository, e.g. calico/go-build
#   TAG         the version tag, derived from committed files only
#   ARCHES      the architectures it ships
#   BUILD_ARGS  NAME=value pairs whose values are set outside the image's
#               directory, such as versions from metadata.mk
#   GO_COMMANDS the Go commands it ships, as package paths from the repo root,
#               e.g. toolchain/cmd/artifact
#
# It must not include lib.Makefile. That file's own edits would change every
# toolchain image's source hash, and some take the better part of an hour to
# build under emulation.

TOOLCHAIN_DIR := $(patsubst %/,%,$(dir $(lastword $(MAKEFILE_LIST))))

BUILDARCH ?= $(shell uname -m | sed -e 's/x86_64/amd64/' -e 's/aarch64/arm64/')
ARCH ?= $(BUILDARCH)

include $(TOOLCHAIN_DIR)/go.mk

# What a published tag was built from: the image's directory, this file, the
# packages its commands build from, and the build args. Untracked files count,
# so a working tree hashes the same before and after it is committed. Computed
# on first use, since go_source_dirs runs a container.
IMAGE_DIR := $(patsubst $(REPO_ROOT)/%,%,$(CURDIR))
compute_source_hash = $(shell cd $(REPO_ROOT) && { \
	git ls-files -co --exclude-standard -- $(IMAGE_DIR) $(patsubst $(REPO_ROOT)/%,%,$(abspath $(TOOLCHAIN_DIR)))/lib.mk $(patsubst $(REPO_ROOT)/%,%,$(abspath $(TOOLCHAIN_DIR)))/go.mk \
		$(foreach d,$(go_source_dirs),':(glob)$(d)/*') | LC_ALL=C sort | xargs sha256sum; \
	echo "$(BUILD_ARGS)"; \
	} | sha256sum | cut -c1-16)
SOURCE_HASH = $(eval SOURCE_HASH := $(compute_source_hash))$(SOURCE_HASH)
SOURCE_HASH_LABEL := org.projectcalico.toolchain.source-hash

# A fixed timestamp makes an unchanged layer rebuild to the same digest, so a
# registry, and every node that pulled the previous tag, already holds it.
SOURCE_DATE_EPOCH ?= 0

# Point at a registry ref to reuse layers across machines, e.g. in CI.
TOOLCHAIN_CACHE_REF ?=
comma := ,
CACHE_FLAGS = $(if $(TOOLCHAIN_CACHE_REF),--cache-from type=registry$(comma)ref=$(TOOLCHAIN_CACHE_REF)-$(ARCH) --cache-to type=registry$(comma)ref=$(TOOLCHAIN_CACHE_REF)-$(ARCH)$(comma)mode=max)

# Extra docker build flags an image needs, e.g. --target.
IMAGE_BUILD_FLAGS ?=

# Files `image` needs first, such as the binaries go_build makes.
IMAGE_PREREQS ?=

.PHONY: image
image: $(IMAGE_PREREQS)
	@case " $(ARCHES) " in *" $(ARCH) "*) ;; *) echo "$(IMAGE) does not ship $(ARCH); it ships $(ARCHES)" >&2; exit 1;; esac
	docker buildx build --progress=plain --platform=linux/$(ARCH) \
		$(foreach a,$(BUILD_ARGS),--build-arg $(a)) \
		--build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) \
		--label $(SOURCE_HASH_LABEL)=$(SOURCE_HASH) \
		--output type=docker,name=$(IMAGE):$(TAG)-$(ARCH),rewrite-timestamp=true \
		$(IMAGE_BUILD_FLAGS) $(CACHE_FLAGS) .
ifeq ($(ARCH),$(BUILDARCH))
	docker tag $(IMAGE):$(TAG)-$(ARCH) $(IMAGE):$(TAG)
endif

# QEMU for building another arch, as lib.Makefile's register does.
BINFMT_IMAGE ?= calico/binfmt:$(BINFMT_VER)
.PHONY: register
register:
ifneq ($(BUILDARCH),$(ARCH))
	docker run --privileged --rm $(BINFMT_IMAGE) --install all
endif

.PHONY: image-all
image-all: $(addprefix sub-image-,$(ARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

# Prints "build" when TAG is not published and "published" when it is
# published from this source. Fails when it is published from different
# source: TAG must move whenever the source does.
#
# A multi-arch tag inspects as a map keyed by platform, a single-arch one as the
# image config itself.
.PHONY: check-published
check-published:
	@if ! config=$$(docker buildx imagetools inspect $(IMAGE):$(TAG) --format '{{json .Image}}' 2>/dev/null); then \
		echo build; exit 0; \
	fi; \
	published=$$(echo "$$config" | jq -r 'if has("config") then . else .["linux/$(firstword $(ARCHES))"] end | .config.Labels["$(SOURCE_HASH_LABEL)"] // ""'); \
	if [ "$$published" = "$(SOURCE_HASH)" ]; then \
		echo published; \
	else \
		echo "$(IMAGE):$(TAG) is published from source $${published:-unknown}, not $(SOURCE_HASH)." >&2; \
		echo "$(TAG_BUMP_HINT)" >&2; \
		exit 2; \
	fi

TAG_BUMP_HINT ?= Move the image's version or revision so it gets a new tag.

# Publishing is CI's. Each arch's tag is pushed from the job that built it, then
# one job joins them, so no job waits on an emulated build it did not run.
.PHONY: push push-manifest
push: var-require-CONFIRM
	docker push $(IMAGE):$(TAG)-$(ARCH)
push-manifest: var-require-CONFIRM
	docker buildx imagetools create -t $(IMAGE):$(TAG) $(foreach a,$(ARCHES),$(IMAGE):$(TAG)-$(a))

# A PR's build goes to the CI registry, never to IMAGE: a published tag is
# immutable, and a PR rebuilds its tag on every push. The source hash in the ref
# keeps two PRs that pick the same tag from overwriting each other, and lets a
# rerun or a second PR with the same source reuse the image.
TOOLCHAIN_CI_REGISTRY ?=
CI_REF = $(TOOLCHAIN_CI_REGISTRY)/$(notdir $(IMAGE)):$(TAG)-$(SOURCE_HASH)
# Steps that use the image run on these, so a PR builds only these.
CI_ARCHES := $(filter amd64 arm64,$(ARCHES))

.PHONY: print-ci-ref ci-exists ci-push ci-manifest var-require-TOOLCHAIN_CI_REGISTRY
print-ci-ref: var-require-TOOLCHAIN_CI_REGISTRY
	@echo $(CI_REF)
# Prints yes when the CI registry already holds this source's image.
ci-exists: var-require-TOOLCHAIN_CI_REGISTRY
	@if docker buildx imagetools inspect $(CI_REF) >/dev/null 2>&1; then echo yes; else echo no; fi
ci-push: var-require-TOOLCHAIN_CI_REGISTRY
	docker tag $(IMAGE):$(TAG)-$(ARCH) $(CI_REF)-$(ARCH)
	docker push $(CI_REF)-$(ARCH)
ci-manifest: var-require-TOOLCHAIN_CI_REGISTRY
	docker buildx imagetools create -t $(CI_REF) $(foreach a,$(CI_ARCHES),$(CI_REF)-$(a))
var-require-TOOLCHAIN_CI_REGISTRY:
	@[ -n "$(TOOLCHAIN_CI_REGISTRY)" ] || { echo "set TOOLCHAIN_CI_REGISTRY" >&2; exit 1; }

# Some consumers outside this repo follow a moving tag (:latest, :master) rather
# than pin one. Only master moves them, after TAG itself is published.
MOVING_TAGS ?=
.PHONY: push-moving
push-moving: var-require-CONFIRM
	$(foreach t,$(MOVING_TAGS),docker buildx imagetools create -t $(IMAGE):$(t) $(IMAGE):$(TAG);)

.PHONY: var-require-CONFIRM
var-require-CONFIRM:
	@[ "$(CONFIRM)" = true ] || { echo "this publishes $(IMAGE):$(TAG); set CONFIRM=true" >&2; exit 1; }

.PHONY: print-tag print-source-hash
print-tag:
	@echo $(TAG)
print-source-hash:
	@echo $(SOURCE_HASH)
