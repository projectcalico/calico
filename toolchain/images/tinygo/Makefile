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

IMAGE ?= calico/tinygo
TINYGO_VERSION := $(shell awk '/^tinygo:/ {t = 1; next} t && $$1 == "version:" {print $$2; exit}' versions.yaml)
# A rebuild that keeps TINYGO_VERSION is published as <version>-1, -2 and so
# on. TINYGO_REV names that full tag, and applies only while its prefix is the
# current TinyGo, so a version bump needs no reset.
TINYGO_REV := 0.34.0-1
TAG := $(if $(filter $(TINYGO_VERSION)-%,$(TINYGO_REV)),$(TINYGO_REV),$(TINYGO_VERSION))
ARCHES := amd64 arm64
BUILD_ARGS :=
TAG_BUMP_HINT := Set TINYGO_REV in this Makefile to the next $(TINYGO_VERSION)-N.

include ../../lib.mk

# Builds test/fixture against the image `make image` built, then checks the
# wasm with the image's own wasm-opt. The fixture links the go-re2 and
# go-libinjection static archives that downstream WAF builds use, so a TinyGo
# or wasi-libc bump that breaks their ABI fails the link here. cre2_new must
# be defined in the module: an env.cre2_* import instead means Envoy would
# refuse to load it with "missing import: env.cre2_new", and neither means
# the optimizer dropped the calls and the check proves nothing.
.PHONY: test
test:
	docker run --rm --platform linux/$(ARCH) --user $$(id -u):$$(id -g) -e HOME=/tmp \
		-v $(CURDIR)/test/fixture:/src:ro -w /src \
		$(IMAGE):$(TAG)-$(ARCH) \
		sh -ec 'go mod download; \
			tinygo build \
				-target=wasip1 \
				-gc=precise -opt=2 -scheduler=none \
				-tags="nottinygc_envoy memoize_builders" \
				-o /tmp/fixture.wasm .; \
			file /tmp/fixture.wasm | grep -q WebAssembly; \
			wasm-opt /tmp/fixture.wasm --print 2>/dev/null > /tmp/fixture.wat; \
			if grep "(import \"env\" \"cre2_" /tmp/fixture.wat >&2; then \
				echo >&2 "FAIL: fixture wasm imports env.cre2_*; a go-re2 bump likely lost the bundled libcre2.a"; \
				exit 1; \
			fi; \
			grep -q "^ (func \$$cre2_new " /tmp/fixture.wat || { echo >&2 "FAIL: cre2_new is not in the fixture wasm"; exit 1; }; \
			echo "OK: fixture wasm links cre2_* internally"'
