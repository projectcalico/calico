#!/usr/bin/env bash
set -e
source /build/buildconfig
set -x

## Upgrade all packages.
apt-get update
apt-get dist-upgrade -y --no-install-recommends

dpkg -l | grep ^ii | sed 's_  _\t_g' | cut -f 2 >/tmp/base.txt

## Install HTTPS support for APT.
$minimal_apt_get_install apt-transport-https ca-certificates
## Install add-apt-repository
$minimal_apt_get_install software-properties-common

grep -Fxvf  /tmp/base.txt <(dpkg -l | grep ^ii | sed 's_  _\t_g' | cut \
-f 2) >/tmp/add-apt.txt

# Ensure UTF-8, required for add-apt-repository call.
locale-gen en_US.UTF-8

# Add new repos and update again
LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8 add-apt-repository -y ppa:cz.nic-labs/bird
add-apt-repository -y ppa:project-calico/icehouse
apt-get update

# Install felix and bird
apt-get install -qy \
        calico-felix \
        bird \
        bird6