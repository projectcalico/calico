#!/usr/bin/env bash

set -x
set -e

# Rebuild the docker container with the latest code.
docker build -t calico-pyi-build -f pyi/Dockerfile .

# Run pyinstaller to generate the distribution directory.
docker run --user $UID --rm -v `pwd`:/code calico-pyi-build /code/pyi/run-pyinstaller.sh

# Package it up.
mkdir -p dist
tar -czf dist/calico-felix.tgz -C pyi/dist calico-felix