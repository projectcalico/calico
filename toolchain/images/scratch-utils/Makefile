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

IMAGE ?= calico/scratch-utils
include versions.env
TAG := $(SCRATCH_UTILS_VERSION)
# The CI runners and the GCE VMs it drives are x86_64.
ARCHES := amd64
GO_COMMANDS := toolchain/cmd/scratch-utils
IMAGE_PREREQS = bin/scratch-utils-$(ARCH)
TAG_BUMP_HINT := Bump SCRATCH_UTILS_VERSION in versions.env.

include ../../lib.mk

# Always rebuilt: its inputs include the root go.mod, and go build's own cache
# makes an unchanged rebuild cheap.
.PHONY: bin/scratch-utils-$(ARCH)
bin/scratch-utils-$(ARCH):
	$(call go_build,toolchain/cmd/scratch-utils,$@)

.PHONY: ut
ut:
	$(call go_test,toolchain/cmd/scratch-utils/...)
	$(call go_test,toolchain/internal/scratchutils/...)

# secret is the one subcommand that needs no GCP: it proves the binary runs
# on scratch and /tmp is writable by the non-root user.
.PHONY: test
test: ut
	docker run --rm -e SCRATCH_UTILS_TEST=x $(IMAGE):$(TAG)-amd64 secret SCRATCH_UTILS_TEST /tmp/x | grep -qx 'created /tmp/x'
