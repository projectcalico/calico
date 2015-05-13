#!/bin/bash

docker run -rm -v `pwd`/:/code calico-build bash -c '/tmp/etcd -data-dir=/tmp/default.etcd/ & nosetests -c nose.cfg'
