#!/bin/bash

set -e

docker build -t calico-build .

cd ..
mkdir -p `pwd`/dist
chmod 777 `pwd`/dist
docker run -u user -v `pwd`/:/code/calico -v `pwd`/dist:/code/dist calico-build pyinstaller calico/calicoctl.py -a -F -s --clean
docker run -u user -v `pwd`/dist:/code/dist calico-build bash -c 'docopt-completion --manual-bash dist/calicoctl && mv calicoctl.sh dist'

echo "Build output is in dist/"
echo "Copy dist/calicoctl.sh to /etc/bash_completion.d/ to get bash completion"
