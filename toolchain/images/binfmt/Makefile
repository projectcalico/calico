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

IMAGE ?= calico/binfmt
TAG := $(BINFMT_VER)
# Only amd64 hosts register emulators for the other architectures.
ARCHES := amd64
BUILD_ARGS := QEMU_VERSION=$(QEMU_VERSION)
GO_COMMANDS := toolchain/cmd/binfmt
IMAGE_PREREQS = bin/binfmt-$(ARCH)
REV_VAR := BINFMT_REV in metadata.mk
TAG_BASE := $(BINFMT_BASE_VER)

include ../../lib.mk

# The tonistiigi/binfmt commit that cmd/binfmt follows.
BINFMT_REVISION := e41434f

# Always rebuilt: its inputs include the root go.mod, and go build's own cache
# makes an unchanged rebuild cheap.
.PHONY: bin/binfmt-$(ARCH)
bin/binfmt-$(ARCH):
	$(call go_build,toolchain/cmd/binfmt,$@,-X main.revision=$(BINFMT_REVISION) -X main.qemuVersion=$(QEMU_VERSION))

# Runs against the image `make image` built.
.PHONY: test
test:
	$(call go_test,toolchain/cmd/binfmt/...)
	@v=$$(docker run --rm $(IMAGE):$(TAG)-amd64 --version 2>&1); echo "$$v"; \
		echo "$$v" | grep -Fqx 'binfmt/$(BINFMT_REVISION) qemu/$(QEMU_VERSION) go/$(GO_VERSION)'
