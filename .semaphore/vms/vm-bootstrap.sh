#!/usr/bin/env bash

set -xeo pipefail

apt-get update -y
apt-get install -y --no-install-recommends apt-transport-https ca-certificates curl software-properties-common

# Add Docker's official GPG key:
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
tee /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Signed-By: /etc/apt/keyrings/docker.asc
EOF

apt-get update -y
apt-get install -y --no-install-recommends git docker-ce docker-ce-cli docker-buildx-plugin containerd.io make iproute2 wireguard
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
touch /tmp/startup-complete
