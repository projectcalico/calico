#!/usr/bin/env bash

# Copyright (c) 2025 Tigera, Inc. All rights reserved.
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

# This script is executed as a startup script for our GCP VMs. It runs at
# instance boot time as root.  Logs go to the VM's serial console.

set -xeo pipefail

# Function to retry a command up to n times with a delay.  When we run more than
# 30 or so VMs, apt-get failures become common.
retry() {
  local n=10
  for i in $(seq 1 $n); do
    "$@" && return 0
    echo "Command '$*' failed, retrying ($i/$n)..."
    sleep 5
  done
  return 1
}

retry apt-get update -y
retry apt-get install -y --no-install-recommends apt-transport-https ca-certificates curl software-properties-common

# Add Docker's official GPG key:
install -m 0755 -d /etc/apt/keyrings
retry curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

ubuntu_codename=$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")

# Add the repository to Apt sources:
tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $ubuntu_codename
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

# Pin the docker version; the node tests use an older docker client so we can't
# let it float.
if [ "$ubuntu_codename" = "jammy" ]; then
  docker_version="=5:20.10.14~3-0~ubuntu-jammy"
elif [ "$ubuntu_codename" = "noble" ]; then
  docker_version="=5:27.5.1-1~ubuntu.24.04~noble"
elif [ "$ubuntu_codename" = "plucky" ]; then
  docker_version="=5:28.3.3-1~ubuntu.25.04~plucky"
else
  docker_version=""
fi

retry apt-get update -y
retry apt-get install -y --no-install-recommends git docker-ce"${docker_version}" docker-ce-cli"${docker_version}" docker-buildx-plugin containerd.io make iproute2 wireguard
usermod -a -G docker ubuntu
modprobe ipip
if [ -s /etc/docker/daemon.json ] ; then
  cat /etc/docker/daemon.json | sed "\$d" | sed "\$s/\$/,/" > /tmp/daemon.json
else
  echo -en '{' > /tmp/daemon.json
fi
cat >> /tmp/daemon.json << EOF
  "ipv6": true,
  "fixed-cidr-v6": "2001:db8:1::/64"
}
EOF

mv /tmp/daemon.json /etc/docker/daemon.json
systemctl restart docker
touch /var/run/startup-script-complete
