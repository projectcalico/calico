import utils
import re

from utils import print_paragraph as para
from utils import print_user_actions as actions
from utils import print_bullet as bullet
from utils import print_next as next
from utils import print_warning as warning

# The candidate version replacement performs most of the required version
# replacements, but replaces build artifact URLs with a dynamic URL that
# can return an artifact for an arbitrary branch.  This is replaced with the
# GitHub release artifact just before the release is actually cut.
CANDIDATE_VERSION_REPLACE = [
    (re.compile(r'__version__\s*=\s*".*"'),
     '__version__ = "{version-no-v}"'),

    (re.compile(r'\*\*release\*\*'),
     '{version}'),

    (re.compile('http://www\.projectcalico\.org/latest/calicoctl'),
     'http://www.projectcalico.org/latest/calicoctl?circleci-branch={version}-candidate'),

    (re.compile(r'git\+https://github\.com/projectcalico/calico\.git'),
     'git+https://github.com/projectcalico/calico.git@{calico-version}'),

    (re.compile(r'git\+https://github\.com/projectcalico/libcalico\.git'),
        'git+https://github.com/projectcalico/libcalico.git@{libcalico-version}'),

    (re.compile(r'calico_docker_ver\s*=\s*"latest"'),
     'calico_docker_ver = "{version}"'),

    (re.compile('calico/node:latest'),
     'calico/node:{version}'),

    (re.compile('calico/node-libnetwork:latest'),
     'calico/node-libnetwork:{libnetwork-version}'),

    (re.compile('calico_libnetwork_ver\s*=\s*"latest"'),
     'calico_libnetwork_ver = "{libnetwork-version}"')
]


# The final version replace handles migrating the dynamic (temporary) URLs to
# point to the Git archives.
FINAL_VERSION_REPLACE = [
    (re.compile('http://www\.projectcalico\.org/latest/calicoctl\?circleci\-branch=.*\-candidate'),
     'https://github.com/projectcalico/calico-docker/releases/tag/{version}'),
]


# Version replacement for the master branch.  We just need to update the
# python version string and the comments.
MASTER_VERSION_REPLACE = [
    (re.compile(r'__version__\s*=\s*".*"'),
     '__version__ = "{version-no-v}-dev"'),

    (re.compile(r'https://github\.com/projectcalico/calico\-docker/blob/.*/README\.md'),
     'https://github.com/projectcalico/calico-docker/blob/{version}/README.md')
]


# Load the globally required release data.
release_data = utils.load_release_data()


# ============== Define the release steps. ===============

def start_release():
    """
    Start the release process, asking user for version information.
    :return:
    """
    para("Your git repository should be checked out to the correct revision "
         "that you want to cut a release with.  This is usually the HEAD of "
         "the master branch.")
    utils.check_or_exit("Are you currently on the correct revision")

    old_version = utils.get_calicoctl_version()
    para("Current version is: %s" % old_version)

    while True:
        new_version = raw_input("New calicoctl version?: ")
        release_type = utils.check_version_increment(old_version, new_version)
        if release_type:
            break
    para("Release type: %s" % release_type)

    para("To pin the calico libraries used by calico-docker, please specify "
         "the name of the requested versions as they appear in the GitHub "
         "releases.")

    calico_version = \
        utils.get_github_library_version("calico (felix)",
                                         "https://github.com/projectcalico/calico")
    libcalico_version = \
        utils.get_github_library_version("libcalico",
                                         "https://github.com/projectcalico/libcalico")
    libnetwork_version = \
        utils.get_github_library_version("libnetwork-plugin",
                                         "https://github.com/projectcalico/libnetwork-plugin")

    release_data["versions"] = {"version": new_version,
                                "version-no-v": new_version[1:],
                                "calico-version": calico_version,
                                "libcalico-version": libcalico_version,
                                "libnetwork-version": libnetwork_version}

    actions()
    bullet("Create a candidate release branch called "
           "'%s-candidate'." % new_version)
    bullet("git checkout -b %s-candidate" % new_version, level=1)
    next("When you have created the branch, re-run the script.")


def update_files():
    """
    Continue the release process by updating the version information in all
    the files.
    """
    utils.check_or_exit("Is your git repository now on the candidate release "
                        "branch")

    # Update the code tree
    utils.update_files(CANDIDATE_VERSION_REPLACE, release_data["versions"])

    new_version = release_data["versions"]["version"]
    para("The codebase has been updated to reference the release candidate "
         "artifacts.")
    actions()
    bullet("Add, commit and push the updated files to "
           "origin/%s-candidate" % new_version)
    bullet("git add --all", level=1)
    bullet('git commit -m "Update version strings for release '
           'candidate %s"' % new_version, level=1)
    bullet("git push origin %s-candidate" % new_version, level=1)
    bullet("Create a DockerHub release called '%s'" % new_version)
    bullet("Monitor the semaphore, CircleCI and Docker builds for this branch "
           "until all have successfully completed.  Fix any issues with the "
           "build.")
    bullet("Run through a subset of the demonstrations:")
    bullet("Ubuntu libnetwork", level=1)
    bullet("CoreOS default networking", level=1)
    para("Follow the URL below to view the correct demonstration instructions "
         "for this release candidate.")
    bullet("https://github.com/projectcalico/calico-docker/tree/%s-candidate" % new_version)
    next("Once you have completed the testing, re-run the script.")


def cut_release():
    """
    The candidate branch has been tested, so cut the actual release.
    """
    utils.check_or_exit("Have you successfully tested your release candidate")

    # Update the code tree once more to set the final GitHub URLs
    utils.update_files(FINAL_VERSION_REPLACE, release_data["versions"])

    new_version = release_data["versions"]["version"]
    para("The codebase has been updated to reference the GitHub release "
         "artifacts.")
    actions()
    bullet("Add, commit and push the updated files to "
           "origin/%s-candidate" % new_version)
    bullet("git add --all", level=1)
    bullet('git commit -m "Update version strings for release '
           '%s"' % new_version, level=1)
    bullet("git push origin %s-candidate" % new_version, level=1)
    bullet("[ideally squash the two commits into one]", level=1)
    bullet("Monitor the semaphore, CircleCI and Docker builds for this branch "
           "until all have successfully completed.  Fix any issues with the "
           "build.")
    bullet("Create a Pull Request and review the changes")
    bullet("Create a GitHub release called '%s'" % new_version)

    para("Attach the calicoctl binary to the release.  It can be downloaded "
         "from the following URL:")
    bullet("http://www.projectcalico.org/latest/calicoctl?circleci-branch=%s-candidate" % new_version)

    para("Once the release has been created on GitHub, perform a final test "
         "of the release:")
    bullet("Run through a subset of the demonstrations:")
    bullet("CoreOS libnetwork", level=1)
    bullet("Ubuntu default networking", level=1)
    next("Once you have completed the testing, re-run the script.")


def change_to_master():
    """
    Version has been releases and tested.
    """
    utils.check_or_exit("Have you successfully tested the release")

    new_version = release_data["versions"]["version"]
    para("The release is now complete.  We now need to update the master "
         "branch and do some general branch and build tidyup.")
    actions()
    bullet("Delete the DockerHub build for this release")
    bullet("Checkout the master branch, and ensure it is up to date")
    bullet("git checkout master", level=1)
    bullet("git pull origin master", level=1)
    bullet("Delete the origin/%s-candidate branch" % new_version)
    bullet("git branch -D %s-candidate" % new_version, level=1)
    bullet("git push origin :%s-candidate" % new_version, level=1)
    next("Once complete, re-run the script.")


def update_master():
    """
    Master branch is now checked out and needs updating.
    """
    utils.check_or_exit("Is your git repository now on master")

    # Update the master files.
    utils.update_files(MASTER_VERSION_REPLACE, release_data["versions"],
                       is_release=False)

    new_version = release_data["versions"]["version"]
    para("The master codebase has now been updated to reference the latest "
         "release.")
    actions()
    bullet("Self review the latest changes to master")
    bullet("Push the changes to origin/master")
    bullet("git add --all", level=1)
    bullet('git commit -m "Update docs to version %s"' % new_version, level=1)
    bullet("git push origin master", level=1)
    bullet("Verify builds are working")
    next("Once complete, re-run the script")


def complete():
    """
    Show complete message
    """
    utils.check_or_exit("Have you pushed the version update to master?")

    warning("Release process is now complete.")


RELEASE_STEPS = [
    start_release,
    update_files,
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
    do_steps()