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

IMAGE ?= calico/go-build
TAG := $(GO_BUILD_VER)
ARCHES := amd64 arm64 ppc64le s390x
BUILD_ARGS := \
	GO_VERSION=$(GO_VERSION) \
	LLVM_VERSION=$(LLVM_VERSION)
REV_VAR := GO_BUILD_REV in metadata.mk
TAG_BASE := $(GO_BUILD_BASE_VER)
IMAGE_PREREQS = bin/artifact-$(ARCH)
GO_COMMANDS := toolchain/cmd/artifact

include ../../lib.mk

# Always rebuilt: its inputs include the root go.mod, and go build's own cache
# makes an unchanged rebuild cheap.
.PHONY: bin/artifact-$(ARCH)
bin/artifact-$(ARCH):
	$(call go_build,toolchain/cmd/artifact,$@)

# Renovate moves Go in go.mod; this refreshes what that leaves stale. It needs
# only curl and sed, so it runs wherever Renovate's post-upgrade tasks do.
.PHONY: update-pins
update-pins:
	@set -e; \
	if grep -q "  go$(GO_VERSION)\.linux-" go.sha256 && grep -qx "goBuildVersion: $(GO_BUILD_VER)" $(METADATA_DIR).argoci/config.yaml; then \
		exit 0; \
	fi; \
	tmp=$$(mktemp); \
	for arch in $(ARCHES); do \
		tarball=go$(GO_VERSION).linux-$$arch.tar.gz; \
		sum=$$(curl -sfL --retry 5 https://dl.google.com/go/$$tarball.sha256); \
		echo "$$sum" | grep -Eq '^[0-9a-f]{64}$$' || { echo "no sha256 for $$tarball" >&2; rm -f $$tmp; exit 1; }; \
		echo "$$sum  $$tarball" >> $$tmp; \
	done; \
	mv $$tmp go.sha256; \
	sed -i 's/^goBuildVersion: .*/goBuildVersion: $(GO_BUILD_VER)/' $(METADATA_DIR).argoci/config.yaml

.PHONY: ut
ut:
	$(call go_test,toolchain/cmd/artifact/...)

# What every consumer assumes is on PATH, hack/install-build-tools included, and
# that build tools stay out. The deeper check is a real build in the image,
# which CI runs.
.PHONY: test
test: ut
	docker run --rm --entrypoint sh $(IMAGE):$(TAG)-$(ARCH) -c 'set -e; \
		go version | grep -F "go$(GO_VERSION) "; \
		clang --version | grep -F "version $(LLVM_VERSION)"; \
		for t in artifact bsdtar checkout changesIn curl su-exec; do \
			command -v $$t >/dev/null || { echo "missing $$t" >&2; exit 1; }; \
		done; \
		for t in gcloud gsutil kube-apiserver kubectl controller-gen deepcopy-gen ginkgo gotestsum goimports stringer protoc protoc-gen-go golangci-lint mockery crane ocb docker-credential-gcr; do \
			! command -v $$t >/dev/null || { echo "$$t is back in the image" >&2; exit 1; }; \
		done; \
		test "$$(stat -c %a /go /go/pkg)" = "$$(printf "1777\n1777")"'
