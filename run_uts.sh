#!/bin/bash
docker run --rm -v `pwd`/calico_containers:/code/calico_containers calico-build bash -c '/tmp/etcd -data-dir=/tmp/default.etcd/ >/dev/null 2>&1 & nosetests calico_containers/tests/unit -c nose.cfg'
