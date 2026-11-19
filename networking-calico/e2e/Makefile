# Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

REGISTRY ?= gcr.io/unique-caldron-775
E2E_IMAGE = openstack-e2e

# Space separated.  No default, because this publishes to a registry the weekly
# e2e runs read from: a push should always name what it is claiming.
IMAGE_TAGS ?=

.PHONY: e2e-image
e2e-image:
	# The rigs are amd64, so an arm64 laptop would otherwise publish an image
	# they cannot run.
	docker build --platform linux/amd64 . -t $(E2E_IMAGE)

# Ordered before e2e-image so a bare `make push` fails in a second, not after a
# multi-minute build.  $(strip) because make strips a whitespace-only value
# given on the command line but not one inherited from the environment, and the
# loop below would then iterate zero times and still succeed.
.PHONY: check-tags
check-tags:
	@test -n "$(strip $(IMAGE_TAGS))" || { echo "IMAGE_TAGS is empty; nothing would be published. Set it, e.g. IMAGE_TAGS=my-branch-fix" >&2; exit 1; }

# Needs a registry login: `gcloud auth configure-docker -q` covers gcr.io.
.PHONY: push
push: check-tags e2e-image
	for tag in $(IMAGE_TAGS); do \
	  docker tag $(E2E_IMAGE) $(REGISTRY)/$(E2E_IMAGE):$$tag && \
	  docker push $(REGISTRY)/$(E2E_IMAGE):$$tag || exit 1; \
	done
