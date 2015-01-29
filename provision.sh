#!/bin/sh

set -e
set -x

git clone https://github.com/metaswitch/calico-docker.git
mv calico-docker/* -t .
mv calico-docker/.git .
mv calico-docker/.gitignore  .

echo "172.17.8.101 core-01" >> /etc/hosts
echo "172.17.8.102 core-02" >> /etc/hosts

chown -R core:core .

