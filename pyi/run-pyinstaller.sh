#!/usr/bin/env bash

set -x
set -e

cd /code/

rm -rf build dist
pyinstaller pyi/calico-felix.spec