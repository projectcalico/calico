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

# Go helpers for the toolchain Makefiles. Every Go program here is in the root
# module, so Go runs from the repo root, in a container, never on the host.
# Needs GO_VERSION, which metadata.mk sets.

REPO_ROOT ?= $(shell git rev-parse --show-toplevel)
GOMODCACHE_HOST ?= $(shell go env GOMODCACHE 2>/dev/null || echo $(HOME)/go/pkg/mod)
GOCACHE_HOST ?= $(shell go env GOCACHE 2>/dev/null || echo $(HOME)/.cache/go-build)

# Go runs in golang:$(GO_VERSION) rather than go-build, which may be the image
# being built, and as the caller so its output is not root-owned.
GO_DOCKER = docker run --rm --user $$(id -u):$$(id -g) \
	-v $(REPO_ROOT):/src -w /src \
	-v $(GOMODCACHE_HOST):/gomodcache -e GOMODCACHE=/gomodcache \
	-v $(GOCACHE_HOST):/gocache -e GOCACHE=/gocache \
	-e HOME=/tmp -e GOPROXY -e GOTOOLCHAIN=local -e GOFLAGS=-buildvcs=false \
	golang:$(GO_VERSION)

# The root module's package directories GO_COMMANDS build from. go.mod is left
# out on purpose: a routine dependency bump must not demand a new tag. The next
# change to an image builds against whatever go.mod pins by then.
go_source_dirs = $(if $(GO_COMMANDS),$(shell $(subst $$$$,$$,$(GO_DOCKER)) go list -deps \
	-f '{{with .Module}}{{if .Main}}{{$$.Dir}}{{end}}{{end}}' $(addprefix ./,$(GO_COMMANDS)) | sed 's|^/src/||'))

# Builds a Go command from the root module into the image's bin/, so the
# Dockerfile copies one file instead of taking the repo as its context. bin/ is
# gitignored; the command's source is hashed through GO_COMMANDS instead.
#   $(call go_build,<package path from the repo root>,<output>,<ldflags>)
define go_build
	mkdir -p $(dir $(2)) $(GOMODCACHE_HOST) $(GOCACHE_HOST)
	$(GO_DOCKER) env CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) \
		go build -trimpath -ldflags '$(3) -s -w' -o $(patsubst $(REPO_ROOT)/%,%,$(abspath $(2))) ./$(1)
endef

#   $(call go_test,<package pattern from the repo root>)
define go_test
	$(GO_DOCKER) go test -count=1 ./$(1)
endef
