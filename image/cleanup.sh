#!/bin/bash
set -e
set -x

# Remove extra packages using dpkg rather than apt-get - this prevents us from
# deleting dependent packages that we still require.
# - Remove any temporary packages installed in the install.sh script.
# - Remove any temporary packages installed in the base.sh script.
echo "Removing extra packages"
grep -Fxvf  /tmp/required.txt <(dpkg -l | grep ^ii | sed 's_  _\t_g' | cut -f 2) | xargs dpkg -r --force-depends
cat /tmp/add-apt.txt | xargs xargs dpkg -r --force-depends

# Remove any other junk created during installation that is not required.
apt-get clean
rm -rf /build
rm -rf /tmp/* /var/tmp/*
rm -rf /var/lib/apt/lists/*
rm -f /etc/dpkg/dpkg.cfg.d/02apt-speedup
