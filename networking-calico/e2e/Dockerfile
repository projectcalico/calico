# Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

FROM python:3.10-slim-bookworm
WORKDIR /calico-test/
# nmap is used by the bare-metal policy tests, which probe TCP ports on
# the rig's nodes from inside this container -- both directly, via
# run_nmap() in test_bare_metal.py, and via assert_open_ports() in
# basetest.py.  It was missing here for as long as those tests were
# unreachable (see the etcdv3 import fix), so nothing noticed.
RUN apt-get update && \
  apt-get install --yes crudini libpython3-dev build-essential git curl sudo sipsak iputils-ping nmap

# Debian packages that the tests install onto rig VMs (which have no internet
# access) via install_dpkg_from_test_rig().  Fetched from the permanent Debian
# archive rather than committed as binary blobs; the checksums pin the exact
# files.  Paths here must agree with DPKGS_DIR settings in
# calicotest/settings.py.
RUN mkdir dpkgs && cd dpkgs && \
  curl -sSLO https://archive.debian.org/debian/pool/main/i/iperf/iperf_2.0.5-3_amd64.deb && \
  curl -sSLO https://archive.debian.org/debian/pool/main/s/scapy/python-scapy_2.2.0-1_all.deb && \
  printf '%s\n' \
    'f4d6cd21bbc17f61afe4b25761ecf7e53f5b9277837b7ba3798b7e4fe4241787  iperf_2.0.5-3_amd64.deb' \
    'a720a5c4e03ec4f009756132559a5058094085b1d2b607b57da39fe241be3d9b  python-scapy_2.2.0-1_all.deb' \
  | sha256sum -c

COPY calicotest       /calico-test/calicotest/
COPY patches          /calico-test/patches/
COPY scripts          /calico-test/scripts/
COPY requirements.txt /calico-test/
RUN ./scripts/prepare-test-runtime.sh
ENTRYPOINT ["/calico-test/calicotest/scripts/e2e-entrypoint.sh"]
