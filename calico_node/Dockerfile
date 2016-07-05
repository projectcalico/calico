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

ENV GLIBC_VERSION 2.23-r1

# Download and install glibc for use by the startup script
RUN apk add --update curl && \
  curl -o glibc.apk -L "https://github.com/andyshinn/alpine-pkg-glibc/releases/download/${GLIBC_VERSION}/glibc-${GLIBC_VERSION}.apk" && \
  apk add --allow-untrusted glibc.apk && \
  curl -o glibc-bin.apk -L "https://github.com/andyshinn/alpine-pkg-glibc/releases/download/${GLIBC_VERSION}/glibc-bin-${GLIBC_VERSION}.apk" && \
  apk add --allow-untrusted glibc-bin.apk && \
  /usr/glibc-compat/sbin/ldconfig /lib /usr/glibc/usr/lib && \
  echo 'hosts: files mdns4_minimal [NOTFOUND=return] dns mdns4' >> /etc/nsswitch.conf && \
  apk del curl && \
  rm -f glibc.apk glibc-bin.apk && \
  rm -rf /var/cache/apk/*

ADD build.sh /build.sh
RUN /build.sh

# Copy in our custom configuration files etc. We do this last to speed up
# builds for developer, as it's the thing they're most likely to change.
ADD start_runit /sbin/
COPY filesystem /
COPY restart-calico-confd /usr/local/bin/

CMD ["/sbin/start_runit"]
