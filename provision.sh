#!/bin/sh

set -e
set -x

git clone https://github.com/metaswitch/calico-docker.git
cd  calico-docker
git checkout ad6ec3bdb23d08faf15050b3e3467a494208c8db
cd ..
mv calico-docker/* -t .
mv calico-docker/.git .
mv calico-docker/.gitignore  .

echo "172.17.8.101 core-01" >> /etc/hosts
echo "172.17.8.102 core-02" >> /etc/hosts

chown -R core:core .

