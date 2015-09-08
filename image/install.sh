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

# Install Confd
curl -L https://github.com/projectcalico/confd/releases/download/v0.10.0-scale/confd -o confd
chmod +x confd

pip install -r /pycalico/requirements.txt
