#!/bin/bash

set -e
set -x

docker build -t calico-build .

cd ..
mkdir -p `pwd`/dist
chmod 777 `pwd`/dist

docker run --rm -v `pwd`/:/code calico-build bash -c '/tmp/etcd & nosetests -c nose.cfg'

docker run --rm -v `pwd`/:/code calico-build \
 pyinstaller calicoctl.py -a -F -s --clean

docker run --rm -v `pwd`/:/code calico-build \
 docopt-completion --manual-bash dist/calicoctl

mv calicoctl.sh dist

echo "Build output is in dist/"
echo "Copy dist/calicoctl.sh to /etc/bash_completion.d/ to get bash completion"
