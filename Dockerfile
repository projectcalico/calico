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
FROM alpine:3.8
MAINTAINER Tom Denham <tom@projectcalico.org>

# Populated by build with the git version.
ARG ver="n/a"
ENV NODE_VERSION=$ver

# Install remaining runtime deps required for felix from the global repository
RUN apk add --no-cache ip6tables ipset iputils iproute2 conntrack-tools runit

# Copy in the filesystem - this contains felix, bird, calico-bgp-daemon etc...
COPY filesystem /

CMD ["start_runit"]
