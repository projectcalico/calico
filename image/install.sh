#!/usr/bin/env bash
set -e
set -x

# Get the current list of required packages (this is used in the clean up
# code to remove the temporary packages that are about to be installed).
dpkg -l | grep ^ii | sed 's_  _\t_g' | cut -f 2 >/tmp/required.txt

# Install temporary packages required for installing Felix and etcd.
apt-get install -qy \
        git \
        python-dev \
        libffi-dev \
        libssl-dev

# Install Felix and python-etcd from the Metaswitch github repos.
pip install git+https://github.com/projectcalico/python-etcd.git
pip install git+https://github.com/projectcalico/calico.git@0.28
pip install git+https://github.com/projectcalico/libcalico.git@v0.1.1

# Install Confd
curl -L https://www.github.com/kelseyhightower/confd/releases/download/v0.9.0/confd-0.9.0-linux-amd64 -o confd
chmod +x confd

pip install -r /pycalico/requirements.txt
