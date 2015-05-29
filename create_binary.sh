#!/bin/bash

set -e
set -x

pushd build_calicoctl
docker build -t calico-build .
popd

mkdir -p `pwd`/dist
chmod 777 `pwd`/dist

docker rm -f pyinstaller || true
# mount calico_containers and dist under /code work directory.  Don't use /code
# as the mountpoint directly since the host permissions may not allow the
# `user` account in the container to write to it.
docker run -v `pwd`/calico_containers:/code/calico_containers \
 -v `pwd`/dist:/code/dist --name pyinstaller \
 -e PYTHONPATH=/code/calico_containers \
 calico-build \
 pyinstaller calico_containers/calicoctl.py -a -F -s --clean
docker rm -f pyinstaller || true

docker rm -f docopt || true
# mount calico_containers and dist under /code work directory.  Don't use /code
# as the mountpoint directly since the host permissions may not allow the
# `user` account in the container to write to it.
docker run -v `pwd`/calico_containers:/code/calico_containers \
 -v `pwd`/dist:/code/dist --name docopt calico-build \
 docopt-completion --manual-bash dist/calicoctl
docker rm -f docopt || true

echo "Build output is in dist/"
echo "Copy dist/calicoctl.sh to /etc/bash_completion.d/ to get bash completion"
