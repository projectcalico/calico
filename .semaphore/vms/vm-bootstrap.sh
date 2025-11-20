#!/usr/bin/env bash

set -xeo pipefail

apt-get update -y
apt-get install -y --no-install-recommends apt-transport-https ca-certificates curl software-properties-common

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --yes --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu ${UBUNTU_VERSION} stable' | tee /etc/apt/sources.list.d/docker.list
apt update -y
apt install -y --no-install-recommends git docker-ce=${DOCKER_VERSION} docker-ce-cli=${DOCKER_VERSION} docker-buildx-plugin containerd.io make iproute2 wireguard
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
