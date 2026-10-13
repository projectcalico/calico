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
 && make -C felix/bpf-gpl -j"$(nproc)" ARCH="$arch" all

RUN go build -buildvcs=false -o /usr/local/bin/calico ./cmd/calico \
 && go build -buildvcs=false -o /usr/local/bin/calico-bpf ./felix/cmd/calico-bpf \
 && go build -buildvcs=false -o /usr/local/bin/operator ./operator/cmd \
 && ln -s calico /usr/local/bin/calicoctl \
 && ln -s calico /usr/local/bin/calico-ipam

RUN go build ./... || echo "WARNING: go build ./... reported failures"
RUN go test -count=1 \
      ./libcalico-go/lib/selector/... \
      ./libcalico-go/lib/backend/syncersv1/updateprocessors/... \
      ./felix/rules/... \
      ./felix/bpf/polprog/... \
      ./apiserver/pkg/registry/projectcalico/authorizer/... \
      ./app-policy/checker/... \
    || echo "WARNING: unit tests reported failures"
