#!/bin/bash

set -e
set -x

pushd build_calicoctl
docker build -t calico-build .
popd

mkdir -p `pwd`/dist
chmod 777 `pwd`/dist

docker rm -f pyinstaller || true
docker run -v `pwd`/:/code --name pyinstaller calico-build \
 pyinstaller calicoctl.py -a -F -s --clean
docker rm -f pyinstaller || true

docker rm -f docopt || true
docker run -v `pwd`/:/code --name docopt calico-build \
 docopt-completion --manual-bash dist/calicoctl
docker rm -f docopt || true


mv calicoctl.sh dist

echo "Build output is in dist/"
echo "Copy dist/calicoctl.sh to /etc/bash_completion.d/ to get bash completion"
