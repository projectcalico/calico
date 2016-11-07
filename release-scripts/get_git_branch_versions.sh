#!/bin/bash -xe

# For some Calico versions, retrieve the documentation for each such
# Calico version from a correspondingly named branch in the 'calico'
# repository on GitHub.
#
# In other words, the point of this script is to allow us to use
# GitHub branches to manage and maintain documentation for different
# Calico versions, instead of simulating a branch management system by
# duplicating and checking in nearly duplicate documentation subtrees
# on the 'master' branch.

GIT_MANAGED_VERSIONS=

function get_version_from_git {
    # Example usage: get_version_from_git v2.1
    #
    # Retrieves and populates (taking 'v2.1' as an example version):
    #
    # - _includes/v2.1, from the content of _includes/master on the
    #   v2.1 Git branch
    #
    # - v2.1, from the content of master on the v2.1 Git branch
    #
    # - _data/v2_1, from the content of _data/master on the v2.1 Git
    #   branch.

    dotted_version=$1
    underscore_version=`echo ${dotted_version} | sed s/\./_/g`

    github=https://github.com/projectcalico/calico.git
    git fetch ${github} ${dotted_version}
    git checkout FETCH_HEAD

    for prefix in _includes/ '' _data/; do
        if [ "${prefix}" = _data/ ]; then
            target=${prefix}/${underscore_version}
        else
            target=${prefix}/${dotted_version}
        fi
        rm -rf ${target}
        cp -a ${prefix}/master ${target}
    done
}

# Populate documentation for the following branches from Git.
for dotted_version in ${GIT_MANAGED_VERSIONS}; do
    get_version_from_git ${dotted_version}
done

# Switch back to the usual 'master' branch.
git checkout master
