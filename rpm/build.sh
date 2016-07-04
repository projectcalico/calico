#!/bin/bash
# Copyright (c) 2016 Tigera, Inc. All rights reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

###############################################################################
# This script will build RPMs for Project Calico; specifically for the
# core Calico code itself, and for Calico's forks of Nova,
# Neutron and Dnsmasq.
#
# To use this script:
#
# - Run rpmdev-setuptree, to set up the directory hierarchy that
#   rpmbuild expects.
#
# - CD into the "rpmbuild" directory.
#
# - Run this script.
###############################################################################

dobuild () {
    repo=$1
    branch=$2

    set -x

    # Clone or update the repository from Github.
    cd ~/rpmbuild
    [ -d $repo ] || git clone https://github.com/projectcalico/${repo}.git
    cd $repo
    git fetch origin
    git reset --hard origin/rpm

    # Infer RPM spec and package names, and link the package spec into
    # ../SPECS.
    spec=`basename rpm/*.spec .spec`
    pkg=${3:-$spec}
    spec=${spec}.spec
    cd ../SPECS
    ln -sf ../${repo}/rpm/$spec

    # Infer the version that the spec wants to build.
    version=`grep Version: $spec | awk '{print $2;}'`

    # Link patches into ../SOURCES.
    cd ../SOURCES
    for f in ../${repo}/rpm/*; do ln -sf $f; done

    # Tar up the Git source, with the naming that rpmbuild expects.
    cd ..
    dir=${pkg}-${version}
    mv $repo $dir
    rm -f SOURCES/${dir}.tar.gz
    tar zcf SOURCES/${dir}.tar.gz $dir
    mv $dir $repo

    # Build.
    cd SPECS
    rpmbuild -ba $spec
}

dobuildx () {
    cd ~/rpmbuild
    echo Building $1...
    if dobuild "$@" > $1.log 2>&1; then
	set +x
	echo $1 OK
    else
	set +x
	echo $1 build failed, see $1.log for details
    fi
}

dobuildx calico master
dobuildx calico-dnsmasq master
dobuildx calico-nova rpm nova
dobuildx calico-neutron rpm neutron
