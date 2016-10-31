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
  do_release.py [--force] [--dry-run] [--skip-validation] [CALICO_DOCKER_VERSION CALICO_VERSION LIBCALICO_VERSION LIBNETWORK_VERSION]

Options:
  -h --help     Show this screen.

"""
import re

from docopt import docopt

import utils
from utils import print_paragraph as para
from utils import print_user_actions as actions
from utils import print_bullet as bullet
from utils import print_next as next
from utils import print_warning as warning
from utils import run
from calico_ctl import __libnetwork_plugin_version__
from calico_ctl import __libcalico_version__
from calico_ctl import __felix_version__

# The candidate version replacement performs most of the required version
# replacements, but replaces build artifact URLs with a dynamic URL that
# can return an artifact for an arbitrary branch.  This is replaced with the
# GitHub release artifact just before the release is actually cut.
# These run from top to bottom.  Be sure to put more specific substitutions
# before more general ones.
CANDIDATE_VERSION_REPLACE = [
    (re.compile(r'__version__\s*=\s*".*"'),
     '__version__ = "{version-no-v}"'),

    (re.compile(r'__libnetwork_plugin_version__\s*=\s*".*"'),
     '__libnetwork_plugin_version__ = "{libnetwork-version}"'),

    (re.compile(r'__libcalico_version__\s*=\s*".*"'),
     '__libcalico_version__ = "{libcalico-version}"'),

    (re.compile(r'__felix_version__\s*=\s*".*"'),
     '__felix_version__ = "{calico-version}"'),

    (re.compile(r'\*\*release\*\*'),
     '{version}'),

    (re.compile(r'http://www\.projectcalico\.org/builds/calicoctl'),
     'http://www.projectcalico.org/builds/calicoctl?circleci-branch={version}-candidate'),

    (re.compile(r'git\+https://github\.com/projectcalico/calico\.git'),
     'git+https://github.com/projectcalico/calico.git@{calico-version}'),

    (re.compile(r'git\+https://github\.com/projectcalico/libcalico\.git@master'),
     'git+https://github.com/projectcalico/libcalico.git@{libcalico-version}'),

    (re.compile(r'git\+https://github\.com/projectcalico/libcalico\.git[^@]'),
     'git+https://github.com/projectcalico/libcalico.git@{libcalico-version}'),

    (re.compile(r'calico_docker_ver\s*=\s*"latest"'),
     'calico_docker_ver = "{version}"'),

    (re.compile(r'calico_node_ver\s*=\s*"latest"'),
     'calico_node_ver = "{version}"'),

    (re.compile(r'calico/node:latest'),
     'calico/node:{version}'),

    (re.compile(r'calico/build:latest'),
     'calico/build:{libcalico-version}'),

    (re.compile(r'https://raw\.githubusercontent\.com/projectcalico/libcalico/master/build-requirements-nosh\.txt'),
     'https://raw.githubusercontent.com/projectcalico/libcalico/{libcalico-version}/build-requirements-nosh.txt'),

    (re.compile(r'calico/node-libnetwork:latest'),
     'calico/node-libnetwork:{libnetwork-version}'),

    (re.compile(r'calico_libnetwork_ver\s*=\s*"latest"'),
     'calico_libnetwork_ver = "{libnetwork-version}"')
]


# The final version replace handles migrating the dynamic (temporary) URLs to
# point to the Git archives.
FINAL_VERSION_REPLACE = [
    (re.compile('http://www\.projectcalico\.org/builds/calicoctl\?circleci\-branch=.*\-candidate'),
     'https://github.com/projectcalico/calico-containers/releases/download/{version}/calicoctl'),
]


# Version replacement for the master branch.  We just need to update the
# python version string and the comments.
MASTER_VERSION_REPLACE = [
    (re.compile(r'__version__\s*=\s*".*"'),
     '__version__ = "{version-no-v}-dev"'),

    (re.compile(r'__libnetwork_plugin_version__\s*=\s*".*"'),
     '__libnetwork_plugin_version__ = "{libnetwork-version}-dev"'),

    (re.compile(r'__libcalico_version__\s*=\s*".*"'),
     '__libcalico_version__ = "{libcalico-version}-dev"'),

    (re.compile(r'__felix_version__\s*=\s*".*"'),
     '__felix_version__ = "{calico-version}-dev"'),

    (re.compile(r'https://github\.com/projectcalico/calico\-containers/blob/v.*/README\.md'),
     'https://github.com/projectcalico/calico-containers/blob/{version}/README.md')
]


# Load the globally required release data.
release_data = utils.load_release_data()


# ============== Define the release steps. ===============

def start_release():
    """
    Start the release process, asking user for version information.
    :return:
    """
    para("Step 1 of 5: Create and push release branch with new versions.")
    para("Your git repository should be checked out to the correct revision "
         "that you want to cut a release with.  This is usually the HEAD of "
         "the master branch.")
    utils.check_or_exit("Are you currently on the correct revision")

    if not arguments["--skip-validation"]:
        # Before asking for version info, perform validation on the current code.
        utils.validate_markdown_uris()

    old_version = utils.get_calicoctl_version()
    para("Current version is: %s" % old_version)

    new_version = arguments["CALICO_DOCKER_VERSION"]
    if not new_version:
        while True:
            new_version = raw_input("New calicoctl version?: ")
            release_type = utils.check_version_increment(old_version, new_version)
            if release_type:
                para("Release type: %s" % release_type)
                break

    calico_version = arguments["CALICO_VERSION"]
    libcalico_version = arguments["LIBCALICO_VERSION"]
    libnetwork_version = arguments["LIBNETWORK_VERSION"]


    if not (calico_version and libcalico_version and libnetwork_version):
        para("To pin the calico libraries used by calico-containers, please specify "
             "the name of the requested versions as they appear in the GitHub "
             "releases.")

        calico_version = \
            utils.get_github_library_version("calico (felix)", __felix_version__,
                                             "https://github.com/projectcalico/calico")
        libcalico_version = \
            utils.get_github_library_version("libcalico", __libcalico_version__,
                                             "https://github.com/projectcalico/libcalico")
        libnetwork_version = \
            utils.get_github_library_version("libnetwork-plugin", __libnetwork_plugin_version__,
                                             "https://github.com/projectcalico/libnetwork-plugin")

    release_data["versions"] = {"version": new_version,
                                "version-no-v": new_version[1:],
                                "calico-version": calico_version,
                                "libcalico-version": libcalico_version,
                                "libnetwork-version": libnetwork_version,
                                }

    bullet("Creating a candidate release branch called "
           "'%s-candidate'." % new_version)
    if arguments['--force']:
        run("git branch -D %s-candidate" % new_version)
    run("git checkout -b %s-candidate" % new_version)

    # Update the code tree
    utils.update_files(CANDIDATE_VERSION_REPLACE, release_data["versions"])

    new_version = release_data["versions"]["version"]
    para("The codebase has been updated to reference the release candidate "
         "artifacts.")

    bullet("Adding, committing and pushing the updated files to "
           "origin/%s-candidate" % new_version)
    run("git add --all")
    run('git commit -m "Update version strings for release '
           'candidate %s"' % new_version)
    if arguments['--force']:
        run("git push -f origin %s-candidate" % new_version)
    else:
        run("git push origin %s-candidate" % new_version)
    actions()
    bullet("Create a DockerHub calico/node release tagged '%s'.  Use the "
           "candidate branch as the name and /calico_node as the Dockerfile "
           "location" % new_version)
    bullet("Monitor the semaphore, CircleCI and Docker builds for this branch "
           "until all have successfully completed.  Fix any issues with the "
           "build.")
    bullet("Run through a subset of the demonstrations.  When running the "
           "vagrant instructions, make sure you are using the candidate "
           "branch (e.g. git checkout %s-candidate):" % new_version)
    bullet("Ubuntu libnetwork", level=1)
    bullet("CoreOS default networking", level=1)
    para("Follow the URL below to view the correct demonstration instructions "
         "for this release candidate.")
    print "https://github.com/projectcalico/calico-containers/tree/%s-candidate" % new_version
    next("Once you have completed the testing, re-run the script.")


def cut_release():
    """
    The candidate branch has been tested, so cut the actual release.
    """
    para("Step 2 of 5: Push final branch, then cut release with binary.")
    utils.check_or_exit("Have you successfully tested your release candidate")

    # Update the code tree once more to set the final GitHub URLs
    utils.update_files(FINAL_VERSION_REPLACE, release_data["versions"])

    new_version = release_data["versions"]["version"]
    para("The codebase has been updated to reference the GitHub release "
         "artifacts.")
    bullet("Adding, committing and pushing the updated files to "
           "origin/%s-candidate" % new_version)
    run("git add --all")
    run('git commit -m "Update version strings for release '
       '%s"' % new_version)
    run("git push origin %s-candidate" % new_version)

    actions()
    bullet("Monitor the semaphore, CircleCI and Docker builds for this branch "
           "until all have successfully completed.  Fix any issues with the "
           "build.")
    bullet("Create a Pull Request against master and review the changes (or "
           "run `git diff origin/master` from the candidate branch). Delete "
           "the pull request after comparing.")
    bullet("Create a GitHub release called '%s'" % new_version)

    para("Attach the calicoctl binaries to the release.  "
         "For linux, It can be downloaded from the following URL:")
    print "http://www.projectcalico.org/builds/calicoctl?circleci-branch=%s-candidate" % new_version
    para("For Windows and Mac it can be downloaded from")
    print "http://capitalship:8080/job/calicoctl-mac/"
    print "http://capitalship:8080/job/calicoctl-windows/"

    para("Once the release has been created on GitHub, perform a final test "
         "of the release:")
    bullet("Run through a subset of the demonstrations.  When running the "
           "vagrant instructions, make sure you are using the tagged release "
           "(e.g. git checkout tags/%s):" % new_version)
    bullet("CoreOS libnetwork", level=1)
    bullet("Ubuntu default networking", level=1)
    bullet("Make sure to check the reported versions of all artifacts.")
    next("Once you have completed the testing, re-run the script.")


def change_to_master():
    """
    Version has been releases and tested.
    """
    para("Step 3 of 5: Remove candidate branch.")
    utils.check_or_exit("Have you successfully tested the release")

    new_version = release_data["versions"]["version"]
    para("The release is now complete.  We now need to update the master "
         "branch and do some general branch and build tidyup.")
    para("Checkout the master branch, and ensure it is up to date")
    run("git checkout master")
    run('git pull origin master')
    para("Delete the origin/%s-candidate branch" % new_version)
    run("git branch -D %s-candidate" % new_version)
    run("git push origin :%s-candidate" % new_version)
    actions()
    bullet("Delete the DockerHub build for this release")

    next("Once complete, re-run the script.")


def update_master():
    """
    Master branch is now checked out and needs updating.
    """
    para("Step 4 of 5: Commit versions and push changes to master.")
    utils.check_or_exit("Is your git repository now on master")

    # Update the master files.
    utils.update_files(MASTER_VERSION_REPLACE, release_data["versions"],
                       is_release=False)

    new_version = release_data["versions"]["version"]
    para("The master codebase has now been updated to reference the latest "
         "release.")
    para("Commit changes to master")
    run("git add --all")
    run('git commit -m "Update docs to version %s"' % new_version)

    actions()
    bullet("Self review the latest changes to master")
    bullet("Run: git diff origin/master", level=1)
    bullet("Push changes to master")
    bullet("Run: git push origin master", level=1)
    bullet("Verify builds are working")
    next("Once complete, re-run the script")


def complete():
    """
    Show complete message
    """
    para("Step 5 of 5: Complete release.")
    utils.check_or_exit("Have you pushed the version updates to master?")

    warning("Release process is now complete.")


RELEASE_STEPS = [
    start_release,
    cut_release,
    change_to_master,
    update_master,
    complete
]


def do_steps():
    """
    Do the next step in the release process.
    """
    step = release_data.get("step-number", 0)
    RELEASE_STEPS[step]()
    step = step+ 1
    if step == len(RELEASE_STEPS):
        release_data.clear()
    else:
        release_data["step-number"] = step
    utils.save_release_data(release_data)

if __name__ == "__main__":
    arguments = docopt(__doc__)
    utils.arguments = arguments
    do_steps()
