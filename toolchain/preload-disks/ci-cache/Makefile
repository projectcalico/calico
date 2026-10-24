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
include ../../go.mk

ARCH ?= amd64

# Static, so build-preload-disk.sh runs it on the host.
.PHONY: bin/disk-image-builder
bin/disk-image-builder:
	$(call go_build,toolchain/cmd/disk-image-builder,$@)

.PHONY: test
test:
	$(call go_test,toolchain/cmd/disk-image-builder/...)
	$(call go_test,toolchain/internal/imager/...)
