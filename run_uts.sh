#!/bin/bash

docker run -rm -v `pwd`/:/code calico-build bash -c '/tmp/etcd -data-dir=/tmp/default.etcd/ & nosetests calico_containers/tests/unit -c nose.cfg'
