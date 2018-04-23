# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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
FROM alpine:3.7
MAINTAINER Tom Denham <tom@projectcalico.org>

# Populated by build with the git version.
ARG ver="n/a"
ENV NODE_VERSION=$ver

# Set the minimum Docker API version required for libnetwork.
ENV DOCKER_API_VERSION 1.21

# Set glibc version
ENV GLIBC_VERSION 2.27-r0

# Download and install glibc for use by non-static binaries that require it.
RUN apk --no-cache add wget ca-certificates libgcc && \
    wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://raw.githubusercontent.com/sgerrand/alpine-pkg-glibc/master/sgerrand.rsa.pub && \
    wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/$GLIBC_VERSION/glibc-$GLIBC_VERSION.apk && \
    wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/$GLIBC_VERSION/glibc-bin-$GLIBC_VERSION.apk && \
    apk add glibc-$GLIBC_VERSION.apk glibc-bin-$GLIBC_VERSION.apk && \
    /usr/glibc-compat/sbin/ldconfig /lib /usr/glibc/usr/lib && \
    apk del wget && \
    rm -f glibc-$GLIBC_VERSION.apk glibc-bin-$GLIBC_VERSION.apk

# Install runit from the community repository, as its not yet available in global
RUN apk add --no-cache --repository "http://alpine.gliderlabs.com/alpine/edge/community" runit

# Install remaining runtime deps required for felix from the global repository
RUN apk add --no-cache ip6tables ipset iputils iproute2 conntrack-tools

# Copy in the filesystem - this contains felix, bird, calico-bgp-daemon etc...
COPY filesystem /

CMD ["start_runit"]
