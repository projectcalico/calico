#!/bin/sh
set -e
set -x

# Install the system packages needed for building the PyInstaller based binary
apk -U add --virtual temp python-dev py-pip alpine-sdk python py-setuptools openssl-dev libffi-dev

# Install python dependencies
pip install --upgrade pip
pip install -r https://raw.githubusercontent.com/projectcalico/libcalico/master/build-requirements-frozen.txt
pip install git+https://github.com/projectcalico/libcalico.git
pip install simplejson 

# Produce a binary - outputs to /dist/controller
pyinstaller /code/controller.py -ayF

# Cleanup everything that was installed now that we have a self contained binary
apk del temp && rm -rf /var/cache/apk/*
rm -rf /usr/lib/python2.7
rm -rf /build
