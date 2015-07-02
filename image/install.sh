#!/usr/bin/env bash
set -e
set -x

dpkg -l | grep ^ii | sed 's_  _\t_g' | cut -f 2 >/tmp/required.txt

apt-get install -qy \
        curl \
        git \
        python-dev \
        libffi-dev \
        libssl-dev

# Install Felix and python-etcd from the Metaswitch github repos.
pip install git+https://github.com/Metaswitch/python-etcd.git
pip install git+https://github.com/Metaswitch/calico.git@0.25

# Install Confd
curl -L https://www.github.com/kelseyhightower/confd/releases/download/v0.9.0/confd-0.9.0-linux-amd64 -o confd
chmod +x confd

pip install -r /pycalico/requirements.txt