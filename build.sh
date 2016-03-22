#!/bin/sh
set -e
set -x

# Install the system packages needed for building the PyInstaller based binary
apk -U add --virtual temp python-dev py-pip alpine-sdk python py-setuptools

# Install python dependencies
pip install -r https://raw.githubusercontent.com/projectcalico/libcalico/master/build-requirements.txt
pip install git+https://github.com/projectcalico/libcalico.git

# Produce a binary - outputs to /dist/policy_agent
pyinstaller /code/policy_agent.py -ayF

# Cleanup everything that was installed now that we have a self contained binary
apk del temp && rm -rf /var/cache/apk/*
rm -rf /usr/lib/python2.7