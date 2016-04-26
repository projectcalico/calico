# Copyright 2015 Metaswitch Networks
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
FROM docker
MAINTAINER Tom Denham <tom@projectcalico.org>
# Install iptables, ip6tables, iproute2, and perform glibc install as per:
# https://github.com/jeanblanchard/docker-alpine-glibc/blob/master/Dockerfile
# We install glibc onto the official docker image (instead of adding docker to 
# the libc image) since glibc installs are more constant than the 
# docker-in-docker installaction and configuration.
RUN apk add --update iptables ip6tables iproute2 curl && \
  curl -o glibc.apk -L "https://github.com/andyshinn/alpine-pkg-glibc/releases/download/2.23-r1/glibc-2.23-r1.apk" && \
  apk add --allow-untrusted glibc.apk && \
  curl -o glibc-bin.apk -L "https://github.com/andyshinn/alpine-pkg-glibc/releases/download/2.23-r1/glibc-bin-2.23-r1.apk" && \
  apk add --allow-untrusted glibc-bin.apk && \
  /usr/glibc-compat/sbin/ldconfig /lib /usr/glibc/usr/lib && \
  echo 'hosts: files mdns4_minimal [NOTFOUND=return] dns mdns4' >> /etc/nsswitch.conf && \
  apk del curl && \
  rm -f glibc.apk glibc-bin.apk && \
  rm -rf /var/cache/apk/*
RUN apk --update add python py-setuptools iproute2 iputils ip6tables ipset

# Could make this container smaller by merging the next three lines with a remove.
RUN apk add git py-pip musl-dev gcc python-dev
ADD requirements.txt /
RUN pip install -r requirements.txt

# The test _framework_ needs to be part of the image - everything else gets volume mounted
ADD tests tests

# The container is used by mounting the code-under-test to /code
WORKDIR /code/

