# Copyright (c) 2015 Tigera, Inc. All rights reserved.
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
FROM ppc64le/alpine:3.6
MAINTAINER David Wilder <wilder@us.ibm.com>

# Running STs in this container requires that it has all dependencies installed
# for executing the tests. Install these dependencies:
RUN apk add --update python python-dev py2-pip py-setuptools openssl-dev libffi-dev tshark \
         netcat-openbsd iptables ip6tables iproute2 iputils ipset curl docker && \
         echo 'hosts: files mdns4_minimal [NOTFOUND=return] dns mdns4' >> /etc/nsswitch.conf && \
         rm -rf /var/cache/apk/*

COPY requirements.txt /requirements.txt
RUN pip install -r /requirements.txt

RUN   apk update \
&&   apk add ca-certificates wget \
&&   update-ca-certificates

# Install etcdctl
RUN wget https://github.com/coreos/etcd/releases/download/v3.2.4/etcd-v3.2.4-linux-ppc64le.tar.gz && \
	tar -xzf etcd-v3.2.4-linux-ppc64le.tar.gz && \
	cd etcd-v3.2.4-linux-ppc64le && \
	ln -s etcdctl /usr/local/bin/

# The container is used by mounting the code-under-test to /code
WORKDIR /code/
