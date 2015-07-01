#!/bin/bash
#set -e
#set -x

echo "Removing extra packages"
grep -Fxvf  /tmp/required.txt <(dpkg -l | grep ^ii | sed 's_  _\t_g' | cut -f 2) | xargs apt-get autoremove -qy
cat /tmp/add-apt.txt | xargs apt-get autoremove -qy

# The above is a little keen. Reinstall one missing required package.
apt-get install --reinstall python-pkg-resources

apt-get clean
rm -rf /build
rm -rf /tmp/* /var/tmp/*
rm -rf /var/lib/apt/lists/*
rm -f /etc/dpkg/dpkg.cfg.d/02apt-speedup
