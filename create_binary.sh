#!/bin/bash
# Copyright 2015 Metaswitch Networks
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
docker run -w /code/dist -v `pwd`/calico_containers:/code/calico_containers \
 -v `pwd`/dist:/code/dist --name docopt calico-build \
 docopt-completion --manual-bash ./calicoctl
docker rm -f docopt || true

echo "Build output is in dist/"
echo "Copy dist/calicoctl.sh to /etc/bash_completion.d/ to get bash completion"
