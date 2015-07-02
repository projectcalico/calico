#!/bin/bash
set -e
set -x

# Remove exta packages using dpkg rather than apt-get - this prevents us from
# deleting dependent packages that we still require.
echo "Removing extra packages"
grep -Fxvf  /tmp/required.txt <(dpkg -l | grep ^ii | sed 's_  _\t_g' | cut -f 2) | xargs dpkg -r --force-depends
cat /tmp/add-apt.txt | xargs xargs dpkg -r --force-depends

apt-get clean
rm -rf /build
rm -rf /tmp/* /var/tmp/*
rm -rf /var/lib/apt/lists/*
rm -f /etc/dpkg/dpkg.cfg.d/02apt-speedup
