#!/usr/bin/env python
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

"""do_release.py

Usage:
  do_release.py [CALICO_PLATFORM_VERSION] [CALICO_DOCKER_VERSION FELIX_VERSION LIBCALICO_VERSION LIBNETWORK_VERSION] [--dry-run]

Options:
  -h --help     Show this screen.

"""
import re
import os
import shutil

from docopt import docopt

import utils
from utils import print_paragraph as para
from utils import print_user_actions as actions
from utils import print_bullet as bullet
from utils import run


VERSION_REPLACE = [
    (re.compile(r'__version__\s*=\s*".*"'),
     '__version__ = "{calico-containers-version-no-v}"'),

    (re.compile(r'__libnetwork_plugin_version__\s*=\s*".*"'),
     '__libnetwork_plugin_version__ = "{libnetwork-version}"'),

    (re.compile(r'__libcalico_version__\s*=\s*".*"'),
     '__libcalico_version__ = "{libcalico-version}"'),

    (re.compile(r'__felix_version__\s*=\s*".*"'),
     '__felix_version__ = "{felix-version}"'),

    (re.compile(r'\*\*release\*\*'),
     '{calico-containers-version}'),

    (re.compile(r'http://www\.projectcalico\.org/builds/calicoctl'),
     'https://github.com/projectcalico/calico-containers/releases/download/{calico-containers-version}/calicoctl'),

    (re.compile(r'calico/ctl:latest'),
     'calico/ctl:{calico-containers-version}'),

    (re.compile(r'git\+https://github\.com/projectcalico/felix\.git'),
     'git+https://github.com/projectcalico/felix.git@{felix-version}'),

    (re.compile(r'git\+https://github\.com/projectcalico/libcalico\.git@master'),
     'git+https://github.com/projectcalico/libcalico.git@{libcalico-version}'),

    (re.compile(r'git\+https://github\.com/projectcalico/libcalico\.git[^@]'),
     'git+https://github.com/projectcalico/libcalico.git@{libcalico-version}'),

    (re.compile(r'calico_docker_ver\s*=\s*"latest"'),
     'calico_docker_ver = "{calico-containers-version}"'),

    (re.compile(r'calico_node_ver\s*=\s*"latest"'),
     'calico_node_ver = "{calico-containers-version}"'),

    (re.compile(r'calico/node:latest'),
     'calico/node:{calico-containers-version}'),

    (re.compile(r'calico/build:latest'),
     'calico/build:{libcalico-version}'),

    (re.compile(r'https://raw\.githubusercontent\.com/projectcalico/libcalico/master/build-requirements-nosh\.txt'),
     'https://raw.githubusercontent.com/projectcalico/libcalico/{libcalico-version}/build-requirements-nosh.txt'),

    (re.compile(r'calico/node-libnetwork:latest'),
     'calico/node-libnetwork:{libnetwork-version}'),

    (re.compile(r'calico_libnetwork_ver\s*=\s*"latest"'),
     'calico_libnetwork_ver = "{libnetwork-version}"'),

    (re.compile(r'calico/kube-policy-controller:latest'),
     'calico/kube-policy-controller:{kube-policy-controller-version}'),

    (re.compile(r'calico/cni:latest'),
     'calico/cni:{calico-cni-version}')
]


def start_release():
    """
    Start the release process, asking user for version information.
    :return:
    """
    new_version = arguments["CALICO_PLATFORM_VERSION"]
    if not new_version:
        new_version = raw_input("New Calico platform version? (vX.Y): ")

    # Check if any of the new version dirs exist already
    new_dirs = ["./%s" % new_version,
            "./_data/%s" % new_version,
            "./_layouts/%s" % new_version]
    for new_dir in new_dirs:
        if os.path.isdir(new_dir):
            # Quit instead of making assumptions.
            para("A versioned folder for %s already exists. Remove and rerun this script?" % new_dir)

    # Create the versioned directories.
    shutil.copytree("./master", new_version)
    # Temporary workdown, use vX_Y instead of vX.Y
    # https://github.com/jekyll/jekyll/issues/5429
    shutil.copytree("./_data/master", "./_data/%s" % new_version.replace(".","_"))
    shutil.copytree("./_includes/master", "./_includes/%s" % new_version)

    run("git add --all")
    run('git commit -m "Copy Master for release %s"' % new_version)

    actions()
    para("Created commit of the raw, unchanged release files.")
    para("Moving on to Version replacement of files.")

    calico_containers_version = arguments["CALICO_DOCKER_VERSION"]
    felix_version = arguments["FELIX_VERSION"]
    libcalico_version = arguments["LIBCALICO_VERSION"]
    libnetwork_version = arguments["LIBNETWORK_VERSION"]

    if not (calico_containers_version and felix_version and libcalico_version and libnetwork_version):
        para("To pin the calico libraries used by calico-containers, please specify "
             "the name of the requested versions as they appear in the GitHub "
             "releases.")
        calico_containers_version = \
            utils.get_github_library_version("calico-containers", "https://github.com/projectcalico/calico-containers")
        felix_version = \
            utils.get_github_library_version("felix", "https://github.com/projectcalico/felix")
        libcalico_version = \
            utils.get_github_library_version("libcalico", "https://github.com/projectcalico/libcalico")
        libnetwork_version = \
            utils.get_github_library_version("libnetwork-plugin", "https://github.com/projectcalico/libnetwork-plugin")
        kube_policy_controller_version = \
            utils.get_github_library_version("kube-policy-controller", "https://github.com/projectcalico/k8s-policy")

        calico_cni_version = \
            utils.get_github_library_version("calico-cni-version", "https://github.com/projectcalico/calico-cni")

    versions = {
        "calico-containers-version": calico_containers_version,
        "calico-containers-version-no-v": calico_containers_version[1:],
        "felix-version": felix_version,
        "libcalico-version": libcalico_version,
        "libnetwork-version": libnetwork_version,
        "kube-policy-controller-version": kube_policy_controller_version,
        "calico-cni-version": calico_cni_version
    }

    # Update the code tree
    utils.update_files(VERSION_REPLACE, versions)

    calico_containers_version = versions["calico-containers-version"]
    para("The codebase has been updated to reference the release artifacts.")
    bullet("Adding, and committing the updated files")
    run("git add --all")
    run('git commit -m "Update version strings for release %s"' % calico_containers_version)
    actions()
    para("You are done with release preparation. You now have two new commits on your branch which add the "
         "necessary files. Please: ")
    bullet("Run through a subset of the demonstrations.  When running the "
           "vagrant instructions, make sure you are using the release "
           "folder (e.g. ./%s):" % new_version)
    bullet("Ubuntu libnetwork", level=1)
    bullet("CoreOS default networking", level=1)
    bullet("CoreOS libnetwork", level=1)
    bullet("Ubuntu default networking", level=1)
    bullet("Make sure to check the reported versions of all artifacts.")
    bullet("Create a Pull Request against master and review the changes (or "
           "run `git diff origin/master` from the candidate branch). "
           "Merge when ready.")

if __name__ == "__main__":
    arguments = docopt(__doc__)
    utils.arguments = arguments
    start_release()
