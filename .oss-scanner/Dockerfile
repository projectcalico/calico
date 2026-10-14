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

# Keep in step with GO_BUILD_VER in metadata.mk.
FROM calico/go-build:1.27.1-llvm21.1.8-k8s1.37.1

# go-build's entrypoint switches to UID 9001, which cannot write /src or use root's build cache.
ENTRYPOINT []

# A go.mod newer than the image fetches its toolchain here, while the network is up, instead of failing.
ENV GOTOOLCHAIN=auto

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

RUN for mod in $(find . -name go.mod -not -path './node_modules/*' -not -path '*/testdata/*'); do \
      (cd "$(dirname "$mod")" && go mod download) || exit 1; \
    done

# The Makefile wraps these in docker run; the scanner has no docker, so call bpf-gpl's Makefile directly.
RUN arch="$(go env GOARCH)" \
 && make -C felix/bpf-gpl libbpf LIBBPF_VERSION="$(sed -n 's/^LIBBPF_VERSION=//p' metadata.mk)" \
 && make -C felix/bpf-gpl/libbpf/src -j"$(nproc)" BUILD_STATIC_ONLY=1 OBJDIR="$arch" EXTRA_CFLAGS=-fPIC \
 && make -C felix/bpf-gpl -j"$(nproc)" ARCH="$arch" all ut-objs map-objs

RUN make -C operator embedded_charts \
 && make -C release internal/defaults/metadata.mk

RUN go build -buildvcs=false -o /usr/local/bin/calico ./cmd/calico \
 && go build -buildvcs=false -o /usr/local/bin/calico-bpf ./felix/cmd/calico-bpf \
 && go build -buildvcs=false -o /usr/local/bin/operator ./operator/cmd \
 && ln -s calico /usr/local/bin/calicoctl \
 && ln -s calico /usr/local/bin/calico-ipam

# ./... skips test-only packages, but naming one fails, so list only packages with sources.
# felix/k8sfv is a package main with no main(); it only builds as a test binary.
RUN go list -f '{{if or .GoFiles .CgoFiles}}{{.ImportPath}}{{end}}' ./... > /tmp/packages \
 && go build -buildvcs=false $(grep -v '/felix/k8sfv$' /tmp/packages)

RUN go test -count=1 \
      ./libcalico-go/lib/selector/... \
      ./libcalico-go/lib/backend/syncersv1/updateprocessors/... \
      ./felix/calc/... \
      ./felix/rules/... \
      ./felix/bpf/polprog/... \
      ./felix/iptables/... \
      ./felix/nftables/... \
      ./apiserver/pkg/registry/projectcalico/authorizer/... \
      ./webhooks/pkg/rbac/... \
      ./app-policy/checker/... \
      ./operator/pkg/controller/csr/... \
      ./typha/pkg/... \
      ./goldmane/pkg/...
