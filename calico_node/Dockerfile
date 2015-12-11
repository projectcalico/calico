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
FROM gliderlabs/alpine:edge
MAINTAINER Tom Denham <tom@projectcalico.org>

ADD start_runit /sbin/
ADD build.sh /build.sh
RUN /build.sh

# Copy in our custom configuration files etc. We do this last to speed up
# builds for developer, as it's the thing they're most likely to change.
COPY filesystem /
COPY restart-calico-confd /usr/local/bin

CMD ["/sbin/start_runit"]
