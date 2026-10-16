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

# calico/base carries UBI's package updates, so it is rebuilt whenever UBI or
# this source moves rather than on a version bump. Its tag is
# <UBI_VERSION>-<epoch>, with the epoch set when it is published, and
# consumers pin CALICO_BASE_VER in metadata.mk.
#
# Without UBI_VERSION, each target runs once per UBI version. Pass the same
# BASE_EPOCH to a later make, e.g. to test what an earlier one built.

include ../../../metadata.mk

IMAGE ?= calico/base
UBI_VERSIONS := ubi9 ubi10
ARCHES := amd64 arm64 ppc64le s390x

# Exported, so every architecture and UBI version gets the same tag.
ifndef BASE_EPOCH
BASE_EPOCH := $(shell date +%s)
endif
export BASE_EPOCH

# The published image needs-rebuild compares against. CALICO_BASE_VER names
# the ubi9 one; the ubi10 one shares its epoch.
BASE_PUBLISHED_VER ?= $(CALICO_BASE_VER)
BASE_PUBLISHED_EPOCH := $(lastword $(subst -, ,$(BASE_PUBLISHED_VER)))

UBI_DIGEST_LABEL := org.projectcalico.toolchain.ubi-digest
ubi_image = registry.access.redhat.com/$(1)/ubi-minimal:latest

ifdef UBI_VERSION

TAG := $(UBI_VERSION)-$(BASE_EPOCH)
BUILD_ARGS := UBI_VERSION=$(UBI_VERSION)
# The UBI digest is not part of the source hash: it moves without the source.
# Resolved at most once per make, so the label and FROM agree.
UBI_DIGEST = $(eval UBI_DIGEST := $(shell docker buildx imagetools inspect $(call ubi_image,$(UBI_VERSION)) --format '{{json .Manifest}}' 2>/dev/null | jq -r '.digest // empty'))$(UBI_DIGEST)
IMAGE_BUILD_FLAGS = --build-arg UBI_DIGEST=$(UBI_DIGEST) --label $(UBI_DIGEST_LABEL)=$(UBI_DIGEST)

include ../../lib.mk

image: ubi-digest

.PHONY: ubi-digest
ubi-digest:
	@test -n "$(UBI_DIGEST)" || { echo "cannot resolve the digest of $(call ubi_image,$(UBI_VERSION))" >&2; exit 1; }
	@echo "$(call ubi_image,$(UBI_VERSION)) is $(UBI_DIGEST)"

# Prints build when the published image for UBI_VERSION was built from
# different source or a different ubi-minimal, or has no labels saying.
.PHONY: needs-rebuild
needs-rebuild:
	@ref=$(IMAGE):$(UBI_VERSION)-$(BASE_PUBLISHED_EPOCH); \
	labels=$$(docker buildx imagetools inspect $$ref --format '{{json .Image}}' 2>/dev/null \
		| jq -c 'if has("config") then . else .["linux/$(firstword $(ARCHES))"] end | .config.Labels // {}'); \
	[ -n "$$labels" ] || labels='{}'; \
	have_src=$$(echo "$$labels" | jq -r '.["$(SOURCE_HASH_LABEL)"] // ""'); \
	have_ubi=$$(echo "$$labels" | jq -r '.["$(UBI_DIGEST_LABEL)"] // ""'); \
	result=published; \
	if [ "$$have_src" != "$(SOURCE_HASH)" ]; then \
		echo "$$ref is built from source $${have_src:-unknown}, not $(SOURCE_HASH)" >&2; result=build; \
	fi; \
	if [ "$$have_ubi" != "$(UBI_DIGEST)" ]; then \
		echo "$$ref is built from ubi-minimal $${have_ubi:-unknown}, not $(or $(UBI_DIGEST),unknown)" >&2; result=build; \
	fi; \
	echo $$result

# Runs against the image `make image` built, which shares this BASE_EPOCH.
.PHONY: test
test:
	docker run --rm --platform linux/$(ARCH) --entrypoint /lib64/libc.so.6 $(IMAGE):$(TAG)-$(ARCH) | head -1
	@set -e; c=$$(docker create --platform linux/$(ARCH) --entrypoint /none $(IMAGE):$(TAG)-$(ARCH)); \
	files=$$(docker export $$c | tar -tv); docker rm $$c >/dev/null; \
	echo "$$files" | grep -Eq '^drwxrwxrwt .* tmp/$$' || { echo "/tmp is not 1777" >&2; exit 1; }; \
	for f in etc/nsswitch.conf lib64/libstdc++.so.6 lib64/libnss_dns.so.2 licenses/Apache-2.0; do \
		echo "$$files" | grep -q " $$f$$" || { echo "$$f is missing" >&2; exit 1; }; \
	done

else

.PHONY: image image-all print-tag print-source-hash test push push-manifest register
image image-all print-tag print-source-hash test push push-manifest register:
	@set -e; for v in $(UBI_VERSIONS); do $(MAKE) --no-print-directory $@ UBI_VERSION=$$v; done

# Prints build if any UBI version needs one, published otherwise.
.PHONY: needs-rebuild
needs-rebuild:
	@set -e; result=published; \
	for v in $(UBI_VERSIONS); do \
		r=$$($(MAKE) --no-print-directory -s needs-rebuild UBI_VERSION=$$v); \
		[ "$$r" = published ] || result=build; \
	done; \
	echo $$result

# The newest ubi9 tag on Docker Hub, which is what needs-rebuild should compare
# against once a publish lands but before Renovate moves CALICO_BASE_VER.
.PHONY: latest-published
latest-published:
	@curl -sfL --retry 5 "https://hub.docker.com/v2/repositories/$(IMAGE)/tags?page_size=100&name=ubi9-" \
		| jq -r '.results[].name' | grep -E '^ubi9-[0-9]+$$' | sort -t- -k2 -n | tail -1

endif
