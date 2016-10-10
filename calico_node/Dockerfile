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
FROM gliderlabs/alpine:3.4
MAINTAINER Tom Denham <tom@projectcalico.org>

ARG LIBCALICO_REPO="https://github.com/projectcalico/libcalico.git"
ARG LIBCALICO_VER="master"
ARG LIBNETWORK_REPO="https://github.com/projectcalico/libnetwork-plugin.git"
ARG LIBNETWORK_VER="master"

# Download and install glibc for use by non-static binaries that require it.
RUN apk --no-cache add wget ca-certificates libgcc && \
    wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://raw.githubusercontent.com/sgerrand/alpine-pkg-glibc/master/sgerrand.rsa.pub && \
    wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.23-r3/glibc-2.23-r3.apk && \
    wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.23-r3/glibc-bin-2.23-r3.apk && \
    apk add glibc-2.23-r3.apk glibc-bin-2.23-r3.apk && \
    /usr/glibc-compat/sbin/ldconfig /lib /usr/glibc/usr/lib && \
    apk del wget ca-certificates && \
    rm -f glibc-2.23-r3.apk glibc-bin-2.23-r3.apk

# Install runit from the community repository, as its not yet available in global
RUN apk add --no-cache --repository "http://alpine.gliderlabs.com/alpine/edge/community" runit

# Install remaining runtime deps required for felix from the global repository
RUN apk add --no-cache ip6tables ipset iputils iproute2 conntrack-tools

# Install Python so libnetwork-plugin can run
RUN apk --no-cache add python py-setuptools

# Copy "shared directory" which can be used to pass custom files (local git repos,
# that can be used by pip install git+file:///)
COPY node_share /tmp/node_share

# Actually install libnetwork-plugin. A python dev environment (and git) is installed so
# libnetwork-plugin can be pip installed.
# Finally the dev environment is removed. Doing this in one image layer minimized the final image size.
RUN apk --no-cache add --virtual temp py-pip git gcc python-dev musl-dev libffi-dev openssl-dev && \
  pip install git+$LIBNETWORK_REPO@$LIBNETWORK_VER && \
  pip install git+$LIBCALICO_REPO@$LIBCALICO_VER && \
  apk del --purge temp

# Copy in the filesystem - this contains felix, bird, gobgp etc...
COPY filesystem /

CMD ["start_runit"]
