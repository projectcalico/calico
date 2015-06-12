#!/usr/bin/env bash

dpkg -l | grep ^ii | sed 's_  _\t_g' | cut -f 2 >/tmp/required.txt

apt-get install -qy \
        python-pip \
        python-dev \
        curl

# Install Confd
curl -L https://www.github.com/kelseyhightower/confd/releases/download/v0.9.0/confd-0.9.0-linux-amd64 -o confd
chmod +x confd

pip install -r /pycalico/requirements.txt