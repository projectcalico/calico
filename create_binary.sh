#!/bin/bash

set -e

mkdir -p `pwd`/dist
chmod 777 `pwd`/dist
docker build -t calico-build .
docker run -u user -v `pwd`/dist:/code/dist --rm calico-build pyinstaller calicoctl.py -a -F -s --clean
docker run -u user -v `pwd`/dist:/code/dist --rm calico-build bash -c 'docopt-completion --manual-bash dist/calicoctl && mv calicoctl.sh dist'

echo "Build output is in dist/"
echo "Copy dist/calicoctl.sh to /etc/bash_completion.d/ to get bash completion"
