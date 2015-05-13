#!/bin/bash

set -e
set -x

docker build -t calico-build .

cd ..
mkdir -p `pwd`/dist
chmod 777 `pwd`/dist

if [[ $CIRCLE_TEST_REPORTS ]]; then
    docker run -v `pwd`/:/code -v $CIRCLE_TEST_REPORTS:/circle_output calico-build \
     bash -c '/tmp/etcd & \
      nosetests -c nose.cfg --cover-html-dir=dist --with-xunit --xunit-file=/circle_output/output.xml'
else
    docker run --rm -v `pwd`/:/code calico-build \
     bash -c '/tmp/etcd & \
      nosetests -c nose.cfg'
fi


docker run -v `pwd`/:/code calico-build \
 pyinstaller calicoctl.py -a -F -s --clean

docker run -v `pwd`/:/code calico-build \
 docopt-completion --manual-bash dist/calicoctl

mv calicoctl.sh dist

echo "Build output is in dist/"
echo "Copy dist/calicoctl.sh to /etc/bash_completion.d/ to get bash completion"
