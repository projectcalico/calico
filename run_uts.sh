#!/bin/bash

set -x
set -e
date
pwd
git status

./create_binary.sh
docker stop pyinstaller docopt
docker rm pyinstaller docopt
docker run -rm -v `pwd`/:/code calico-build bash -c '/tmp/etcd & nosetests -c nose.cfg'

# BE CAREFUL
rm -rf .coverage cover/ default.etcd/
