#!/bin/bash

set -x
set -e
date
pwd
git status

nosetests calico_containers/tests/st -s
