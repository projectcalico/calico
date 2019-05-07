# Copyright (c) 2015-2019 Tigera, Inc. All rights reserved.
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


# NOTE: This Dockerfile should be kept in-sync with the one in calico/node.
# This ensures that testing of Felix in this repository is done in the same
# userspace environment as it will be deployed in calico/node.
FROM calico/bpftool:v5.0-amd64 as bpftool

FROM debian:9.8-slim
LABEL maintainer "Shaun Crampton <shaun@tigera.io>"

# Install a backported version of iptables to ensure we have version 1.6.2
# Similarly for iproute2, we want a more recent version for BPF support.
RUN printf "deb http://deb.debian.org/debian stretch-backports main\n" > /etc/apt/sources.list.d/backports.list \
    && apt-get update \
    && apt-get -t stretch-backports install -y iptables iproute2

# Install remaining runtime deps required for felix from the global repository
RUN apt-get update && apt-get install -y \
    ipset \
    iputils-arping \
    iputils-ping \
    iputils-tracepath \
    # Need arp
    net-tools \
    conntrack \
    runit \
    # Need kmod to ensure ip6tables-save works correctly
    kmod \
    # Need netbase in order for ipset to work correctly
    # See https://github.com/kubernetes/kubernetes/issues/68703
    netbase \
    # Also needed (provides utilities for browsing procfs like ps)
    procps \
    ca-certificates \
    # Felix FV tests require wget
    wget

ADD felix.cfg /etc/calico/felix.cfg
ADD calico-felix-wrapper /usr/bin

# Put our binary in /code rather than directly in /usr/bin.  This allows the downstream builds
# to more easily extract the Felix build artefacts from the container.
ADD bin/calico-felix-amd64 /code/calico-felix
RUN ln -s /code/calico-felix /usr/bin
COPY --from=bpftool /bpftool /usr/bin
WORKDIR /code

# Since our binary isn't designed to run as PID 1, run it via the tini init daemon.
ENV TINI_VERSION v0.18.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static-amd64 /sbin/tini
RUN chmod +x /sbin/tini
ENTRYPOINT ["/sbin/tini", "--"]

# Run felix (via the wrapper script) by default
CMD ["/usr/bin/calico-felix-wrapper"]
