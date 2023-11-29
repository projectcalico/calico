# Copyright (c) 2015 Tigera, Inc. All rights reserved.
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
#
#
### calico/test
# This image is used by various calico repositories and components to run UTs
# and STs. It has libcalico, nose, and other common python libraries
# already installed
#
# For UTs:
#  - volume mount in python code that uses libcalico
#  - volume mount in your unit tests for this code
#  - run 'nosetests'
#
# This container can also be used for running STs written in python. This
# eliminates all dependencies besides docker on the host system to enable
# running of the ST frameworks.
# To run:
# - volume mount the docker socket, allowing the STs to launch docker
#   containers alongside itself.
# - eliminate most isolation, (--uts=host --pid=host --net=host --privileged)
# - volume mount your ST source code
# - run 'nosetests'

FROM docker:18.09

ARG ETCD_VERSION
ARG TARGETARCH

# Running STs in this container requires that it has all dependencies installed
# for executing the tests. Install these dependencies:
RUN apk add --no-cache \
    curl \
    gcc \
    ip6tables \
    iproute2 \
    ipset \
    iptables \
    iputils \
    jq \
    libffi-dev \
    musl-dev \
    netcat-openbsd \
    openssl-dev \
    py-setuptools \
    py2-pip \
    python \
    python-dev \
    tshark

# Install etcdctl
RUN curl -sfL https://github.com/coreos/etcd/releases/download/${ETCD_VERSION}/etcd-${ETCD_VERSION}-linux-${TARGETARCH}.tar.gz | \
    tar xz --strip-components 1 -C /usr/local/bin etcd-${ETCD_VERSION}-linux-${TARGETARCH}/etcdctl

COPY requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

# The container is used by mounting the code-under-test to /code
WORKDIR /code/
