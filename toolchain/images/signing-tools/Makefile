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

include ../../../metadata.mk

IMAGE ?= calico/signing-tools
include versions.env
TAG := $(SIGNING_TOOLS_VERSION)
# The release runners are x86_64, and versions.env pins amd64 checksums only.
ARCHES := amd64
TAG_BUMP_HINT := Bump SIGNING_TOOLS_VERSION in versions.env.

# Not BUILD_ARGS: versions.env lives in this directory, which the source hash covers.
IMAGE_BUILD_FLAGS := \
	--build-arg COSIGN_VERSION=$(COSIGN_VERSION) \
	--build-arg COSIGN_SHA256=$(COSIGN_SHA256_AMD64) \
	--build-arg SYFT_VERSION=$(SYFT_VERSION) \
	--build-arg SYFT_SHA256=$(SYFT_SHA256_AMD64)

include ../../lib.mk

.PHONY: test
test:
	docker run --rm $(IMAGE):$(TAG)-amd64 cosign version
	docker run --rm $(IMAGE):$(TAG)-amd64 syft version
