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

IMAGE ?= calico/rust-build
TAG := $(RUST_BUILD_VER)
ARCHES := amd64 arm64 ppc64le s390x
BUILD_ARGS := RUST_VERSION=$(RUST_VERSION)
TAG_BUMP_HINT := Set RUST_BUILD_REV in metadata.mk to the next $(RUST_VERSION)-N.

include ../../lib.mk

# Runs against the image `make image` built. On amd64 it also links an arm64
# binary, the way component builds cross-compile with this image.
.PHONY: test
test:
	docker run --rm --platform linux/$(ARCH) $(IMAGE):$(TAG)-$(ARCH) sh -ec '\
		rustc --version | grep -F "rustc $(RUST_VERSION) "; \
		cargo clippy --version; \
		rustfmt --version; \
		protoc --version; \
		cd /tmp && cargo new -q hello && cd hello; \
		cargo build -q && ./target/debug/hello; \
		if [ "$(ARCH)" = amd64 ]; then \
			CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=clang \
			CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=--target=aarch64-linux-gnu -C link-arg=--sysroot=/usr/aarch64-linux-gnu/sys-root -C link-arg=-fuse-ld=lld" \
			cargo build -q --target aarch64-unknown-linux-gnu; \
			aarch64-linux-gnu-readelf -h target/aarch64-unknown-linux-gnu/debug/hello | grep -q AArch64; \
		fi'
