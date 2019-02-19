# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
# Copyright IBM Corp. 2017
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
ARG QEMU_IMAGE=calico/go-build:latest
ARG BIRD_IMAGE=calico/bird:latest

FROM ${QEMU_IMAGE} as qemu
FROM ${BIRD_IMAGE} as bird

FROM s390x/debian:buster-slim as bpftool-build

COPY --from=qemu /usr/bin/qemu-s390x-static /usr/bin/

RUN apt-get update && \
apt-get upgrade -y && \
apt-get install -y --no-install-recommends \
    gpg gpg-agent libelf-dev libmnl-dev libc-dev iptables libgcc-8-dev \
    bash-completion binutils binutils-dev make git curl \
    ca-certificates xz-utils gcc pkg-config bison flex build-essential && \
apt-get purge --auto-remove && \
apt-get clean

WORKDIR /tmp

RUN \
git clone --depth 1 -b master git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git && \
cd linux/tools/bpf/bpftool/ && \
sed -i '/CFLAGS += -O2/a CFLAGS += -static' Makefile && \
sed -i 's/LIBS = -lelf $(LIBBPF)/LIBS = -lelf -lz $(LIBBPF)/g' Makefile && \
printf 'feature-libbfd=0\nfeature-libelf=1\nfeature-bpf=1\nfeature-libelf-mmap=1' >> FEATURES_DUMP.bpftool && \
FEATURES_DUMP=`pwd`/FEATURES_DUMP.bpftool make -j `getconf _NPROCESSORS_ONLN` && \
strip bpftool && \
ldd bpftool 2>&1 | grep -q -e "Not a valid dynamic program" \
	-e "not a dynamic executable" || \
	( echo "Error: bpftool is not statically linked"; false ) && \
mv bpftool /usr/bin && rm -rf /tmp/linux

FROM s390x/alpine:3.8
MAINTAINER LoZ Open Source Ecosystem (https://www.ibm.com/developerworks/community/groups/community/lozopensource)

ARG ARCH=s390x
# Set the minimum Docker API version required for libnetwork.
ENV DOCKER_API_VERSION 1.21

# Enable non-native builds of this image on an amd64 hosts.
# This must be the first RUN command in this file!
# we only need this for the intermediate "base" image, so we can run all the apk and other commands
# when running on a kernel >= 4.8, this will become less relevant
COPY --from=qemu /usr/bin/qemu-${ARCH}-static /usr/bin/

# Install remaining runtime deps required for felix from the global repository
RUN apk add --no-cache ip6tables ipset iputils iproute2 conntrack-tools runit file ca-certificates

# Copy our bird binaries in
COPY --from=bird /bird* /bin/

# Copy in the filesystem - this contains felix, calico-bgp-daemon etc...
COPY filesystem/ /

# Add in confd config and templates
COPY vendor/github.com/kelseyhightower/confd/etc/calico/ /etc/calico/

# Copy in the calico-node binary
COPY dist/bin/calico-node-${ARCH} /bin/calico-node

COPY --from=bpftool-build /usr/bin/bpftool /bin

RUN rm /usr/bin/qemu-${ARCH}-static

CMD ["start_runit"]
