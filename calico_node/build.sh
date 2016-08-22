#!/bin/sh
# Copyright (c) 2016 Tigera, Inc. All rights reserved.

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

set -e
set -x

# These packages make it into the final image.
# Install runit from the community repository, as its not yet available in global
apk add --update-cache --repository "http://alpine.gliderlabs.com/alpine/edge/community" runit
# Install remaining runtime deps from the global repository
apk add --update-cache python py-setuptools libffi ip6tables ipset iputils iproute2 yajl conntrack-tools

# Add these build-tools packages under a virtual package named 'temp' which 
# will be uninstalled post-build.
apk add --virtual temp python-dev libffi-dev py-pip alpine-sdk curl

# Install Confd
curl -L https://github.com/projectcalico/confd/releases/download/v0.10.0-scale/confd.static -o /sbin/confd

# Copy patched BIRD daemon with tunnel support.
curl -L https://github.com/projectcalico/calico-bird/releases/download/v0.1.0/bird -o /sbin/bird
curl -L https://github.com/projectcalico/calico-bird/releases/download/v0.1.0/bird6 -o /sbin/bird6
curl -L https://github.com/projectcalico/calico-bird/releases/download/v0.1.0/birdcl -o /sbin/birdcl
chmod +x /sbin/*

# Install Felix and libcalico
pip install git+https://github.com/projectcalico/calico.git
pip install git+https://github.com/projectcalico/libcalico.git

# Output the python library list
pip list > libraries.txt

# Cleanup
apk del temp && rm -rf /var/cache/apk/*
