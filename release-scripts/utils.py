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

import os
import pickle
import re
import shutil
import sys
import textwrap
import urllib2
from os import path
import subprocess

# The root directory
PATH_ROOT = path.dirname(path.dirname(path.realpath(__file__)))
sys.path.append(path.join(PATH_ROOT, "calicoctl"))
from calico_ctl import __version__

# Path names relative to the root of the project
PATH_CALICOCTL_NODE = path.join("calicoctl", "calico_ctl", "node.py")
PATH_CALICOCTL_INIT = path.join("calicoctl", "calico_ctl", "__init__.py")
PATH_CALICONODE_BUILD = path.join("calico_node", "build.sh")
PATH_MAKEFILE = "Makefile"
PATH_MAIN_README = "README.md"
PATH_DOCS = "docs"
PATH_RELEASE_DATA = ".releasedata"
PATH_BUILDING = path.join(PATH_DOCS, "Building.md")

# Regexes for calico-containers version format.
INIT_VERSION = re.compile(r'__version__\s*=\s*"(.*)"')
VERSION_RE = re.compile(r'^v(\d+)\.(\d+)\.(\d+)$')
VERSION_NAME_RE = re.compile(r'^v(\d+)\.(\d+)\.(\d+)[.-](\w+)$')

# Regex for MD file URL matching
MD_URL_RE = re.compile(r'\[([^\[\]]*)\]\(([^()]*)\)')

# Regex for matching the main README.
README_RE = re.compile(r'https://github\.com/projectcalico/calico\-containers/blob/.*/README\.md')

# Files to include in the list of files to automatically update.  All file
# paths are relative to the project root.
UPDATE_FILES_STATIC = [PATH_MAIN_README,
                       PATH_CALICOCTL_NODE,
                       PATH_CALICONODE_BUILD,
                       PATH_CALICOCTL_INIT,
                       PATH_MAKEFILE]
UPDATE_FILES_DIRS = [PATH_DOCS]
UPDATE_FILES_EXCLUDE = [PATH_BUILDING]
UPDATE_FILES_RE = re.compile("(.*\.md)|(Vagrantfile)|(user\-data\-.*)|(.*\.yaml)")

# Indicators separating blocks of master only and release only text.
BLOCK_INDICATOR_MASTER_START = "<!--- master only -->"
BLOCK_INDICATOR_MASTER_ELSE = "<!--- else"
BLOCK_INDICATOR_MASTER_END = "<!--- end of master only -->"

arguments = {}

def run(command):
    """
    Run or print a command
    :param command: The command to run
    :return: None
    """
    if arguments['--dry-run']:
        print command
    else:
        subprocess.call(command, shell=True)


def get_update_file_list():
    """
    Return a set of files that need to be updated with new version strings.
    :return: A set of files that need to be updated with release information.
    """
    update_files_list = set(UPDATE_FILES_STATIC)
    update_files_exclude = set(UPDATE_FILES_EXCLUDE)
    for dirn in UPDATE_FILES_DIRS:
        for root, dirs, files in os.walk(path.join(PATH_ROOT, dirn)):
            for filen in files:
                if UPDATE_FILES_RE.match(filen):
                    filep = path.join(root, filen)
                    update_files_list.add(path.relpath(filep, PATH_ROOT))
    return update_files_list - update_files_exclude


def replace_file(filename, contents):
    """
    Perform a safe update of the file, keeping a backup until the new file has
    been written.  File mode is transferred to the new file.

    :param filename: The name of the file (relative to project root)
    :param contents: The contents of the files as a list of lines, each line
    should include the newline character.
    """
    filename = path.join(PATH_ROOT, filename)
    filename_bak = "%s.release.bak" % filename
    os.rename(filename, filename_bak)
    with open(filename, "w") as out_file:
        out_file.write("".join(contents))
    shutil.copymode(filename_bak, filename)
    os.remove(filename_bak)


def load_file(filename):
    """
    Load the contents of a file into a string.
    :param filename: The name of the file (relative to the project root)
    :return: The contents of the files as a list of lines.  Each line includes
    the newline character.
    """
    with open(path.join(PATH_ROOT, filename), "r") as in_file:
        return in_file.readlines()


def get_calicoctl_version():
    """
    Determine the current version from the calicoctl __init__.py
    :return: The current calicoctl version
    """
    return "v" + __version__


def check_version_increment(old_version, new_version):
    """
    Check that the new version is a valid increment from the old version.
    :param old_version:
    :param new_version:
    :return: The increment type
    """
    old_version_tuple = _get_version_tuple(old_version)
    new_version_tuple = _get_version_tuple(new_version)

    if new_version_tuple is None:
        print_warning("The format of version '%s' is not valid.  It should be"
                      " in the form vX.Y.Z or vX.Y.Z-ABCD" % new_version)
        return None

    old_major, old_minor, old_patch, old_name = old_version_tuple
    new_major, new_minor, new_patch, new_name = new_version_tuple

    if (new_major == old_major + 1 and
        new_minor == 0 and
        new_patch == 0):
        return "Major version increment"

    if (new_major == old_major and
        new_minor == old_minor + 1 and
        new_patch == 0):
        return "Minor version increment"

    if (new_major == old_major and
        new_minor == old_minor and
        new_patch == old_patch + 1):
        return "Patch update"

    if (new_major == old_major and
        new_minor == old_minor and
        new_patch == old_patch and
        new_name != old_name):
        return "Development update"

    print_warning("The version increment is not valid.  Expecting a single "
                  "increment of major, minor or patch.")
    return None


def _get_version_tuple(version_string):
    """
    Return the version tuple from the string.
    :param version_string:
    :return:
    """
    match = VERSION_RE.match(version_string)
    if match:
        return (int(match.group(1)),
                int(match.group(2)),
                int(match.group(3)),
                None)
    match = VERSION_NAME_RE.match(version_string)
    if match:
        return (int(match.group(1)),
                int(match.group(2)),
                int(match.group(3)),
                match.group(4))

    return None


def update_files(regex_replace_list, values, is_release=True):
    """
    Update files based on the supplied regex replace list and format values.
    :param regex_replace_list: A list of tuples of (regex, replace format string)
    :param values: The values to substitute in the replace format strings.
    :param is_release: Whether this is a release branch.  If so, remove the
    master only text.
    """
    # Copy the regex replace list, but update the replace strings to include
    # the supplied values.
    regex_replace_list = [(reg, repl.format(**values)) for (reg, repl) in regex_replace_list]
    filens = get_update_file_list()
    for filen in filens:
        old_lines = load_file(filen)
        new_lines = []
        include = True
        master_block = False
        for line in old_lines:
            if is_release:
                if line.startswith(BLOCK_INDICATOR_MASTER_START):
                    assert not master_block, "<!--- start indicator with no end in file %s" % filen
                    master_block = True
                    include = False
                    continue
                if line.startswith(BLOCK_INDICATOR_MASTER_ELSE):
                    assert master_block, "<!--- else indicator with no start in file %s" % filen
                    include = True
                    continue
                if line.startswith(BLOCK_INDICATOR_MASTER_END):
                    assert master_block, "<!--- end indicator with no start in file %s" % filen
                    include = True
                    master_block = False
                    continue
            if include:
                for regex, replace in regex_replace_list:
                    line = regex.sub(replace, line)
                new_lines.append(line)
        assert not master_block, "<!--- start indicator with no end in file %s" % filen
        replace_file(filen, new_lines)


def load_release_data():
    """
    Load the release data.  This always prints a warning if the release data
    contains any release data.
    :return:
    """
    filen = path.join(PATH_ROOT, PATH_RELEASE_DATA)
    try:
        with open(filen, "r") as in_file:
            data = pickle.load(in_file)

        if data:
            print_warning("You are continuing an existing release.  If this "
                          "an error, delete the release data file and try "
                          "again.  "
                          "Filename = see below")
            print filen

        return data
    except:
        return {}

def save_release_data(release_data):
    """
    Save the release data.
    :param release_data: The release data to pickle.
    """
    assert isinstance(release_data, dict)
    filen = path.join(PATH_ROOT, PATH_RELEASE_DATA)
    filen_bak = "%s.bak" % filen
    try:
        if path.exists(filen_bak):
            print_warning("Backup release data is found indicating an unclean "
                          "save.  If this is expected, delete the file and "
                          "try again.  "
                          "Filename=%s" % filen_bak)
            sys.exit(1)

        if path.exists(filen):
            os.rename(filen, filen_bak)

        with open(filen, "w") as out_file:
            pickle.dump(release_data, out_file)

        if path.exists(filen_bak):
            os.remove(filen_bak)
    except Exception, e:
        print_warning("Unable to store release data: %s" % e)
        sys.exit(1)


def get_github_library_version(name, current, url):
    """
    Ask the user for the version of a GitHub library.
    :param name: A friendly name.
    :param current: The current version
    :param url: The GitHub repo.
    :return:
    """
    while True:
        # For the release, make sure the default versions do not include "-dev"
        if current.endswith("-dev"):
            current = current[:-4]
        version = raw_input("Version of %s [currently %s]?: " % (name, current))
        if not version:
            # Default to current if user just presses enter
            version = current

        if not url_exists("%s/releases/tag/%s" % (url, version)):
            print_warning("The version of %s is not valid.  Please check the "
                          "GitHub releases for exact naming at "
                          "%s/releases" % (name, url))
            continue
        return version


def url_exists(url):
    """
    Check that a URL exists.
    :param url:
    :return: True if it exists, False otherwise.
    """
    # Check for URLs we can't validate
    if url.startswith("https://kiwiirc.com"):
        return True
    if url.startswith("https://www.projectcalico.org"):
        return True

    try:
        urllib2.urlopen(url)
        return True
    except urllib2.HTTPError, e:
        print_bullet("Hit error reading %s: %s" % (url, e))
        return False
    except urllib2.URLError, e:
        print_bullet("Hit error reading %s: %s" % (url, e))
        return False


def print_paragraph(msg):
    """
    Print a fixed width (80 chars) paragraph of text.
    :param msg: The msg to print.
    """
    print
    print "\n".join(textwrap.wrap(msg, width=80))


def print_warning(msg):
    """
    Print a warning message
    :param msg: The msg to print
    """
    print
    print "*" * 80
    print "\n".join(textwrap.wrap(msg, width=80))
    print "*" * 80


def print_user_actions():
    """
    Print a user actions heading.
    """
    print
    print "=" * 80
    print "  User Actions"
    print "=" * 80


def print_bullet(msg, level=0):
    """
    Print a bulleted message.

    :param msg:  The msg to print
    :param level:  The level of bullet
    """
    margin = 1 + (3 * (level + 1))
    lines = textwrap.wrap(msg, width=80 - margin)
    print " " * (margin - 3) + "-  " + lines[0]
    for line in lines[1:]:
        print " " * margin + line


def print_next(msg):
    """
    Print the next step message.
    :param msg: The message to display
    """
    print
    print "-" * 80
    print "\n".join(textwrap.wrap(msg, width=80))
    print "=" * 80


def check_or_exit(msg):
    """
    Ask for a yes/no response and exit if the response is no.
    :param msg:
    :return:
    """
    while True:
        user_input = raw_input("%s (y/n): " % msg).lower()
        if user_input in ['y', 'yes']:
            print
            return
        if user_input in ['n', 'no']:
            print
            print_warning("Please complete the required steps and then "
                          "re-run the script.")
            sys.exit(1)


def validate_markdown_uris():
    """
    Validate that all of the URIs in the markdown files are accessible.
    """
    print "Validating URIs in markdown files"
    all_valid = True
    all_md_files = [f for f in get_update_file_list() if f.endswith(".md")]
    for filename in all_md_files:
        lines = load_file(filename)
        found_analytic_url = False
        for line in lines:
            for name, uri in MD_URL_RE.findall(line):
                if name == "Analytics":
                    found_analytic_url = True
                    valid = validate_analytics_url(filename, uri)
                else:
                    valid = validate_uri(filename, uri)
                all_valid = all_valid and valid
        if not found_analytic_url:
            print_bullet("%s: No analytics URL in file" % filename)
    if not all_valid:
        print_warning("Errors detected in markdown file URIs.  Please correct "
                      "the errors highlighted above and then re-run the"
                      "script.")
        sys.exit(1)
    print "Validation complete"


def validate_uri(filename, uri):
    """
    Validate a URI exists, either by checking the file exists, or by checking
    the URL is accessbile.
    :param filename:  The filename of the MD file containing the URI.
    :param uri:  The URI to validate (either a web URL, or a filename)
    :return:  True if URI is valid and accessible
    """
    if uri.startswith("http"):
        # Validating a URL.  Don't validate the shield URLs.
        if uri.startswith("https://img.shields.io"):
            return True
        if uri.startswith("https://badge.imagelayers.io"):
            return True

        # There should no calico-containers URL except for:
        # - The README URLs which we skip since these are auto-generated
        # - Issues (which we can validate)
        # - Releases (which we can validate)
        # Everything else should be specified with a relative path.
        if (uri.startswith("https://github.com/projectcalico/calico-containers") or
            uri.startswith("https://www.github.com/projectcalico/calico-containers")):

            if README_RE.match(uri):
                return True

            # If an explicit version has been specified then keep it in, but warn the user.
            if (uri.startswith("https://github.com/projectcalico/calico-containers/blob") or
                uri.startswith("https://www.github.com/projectcalico/calico-containers/blob")):
                print_bullet("%s: WARNING: Should this be a relative URL?: %s" % (filename, uri))
                return True

            if ((uri.find("/calico-containers/issues") < 0) and
                (uri.find("/calico-containers/releases") < 0)):
                print_bullet("%s: Do not specify calico-containers file using a URL, "
                             "specify using a relative path: %s" % (filename, uri))
                return False

        if not url_exists(uri):
            print_bullet("%s: URL is not valid: %s" % (filename, uri))
            return False
        else:
            return True
    else:
        # Validating a file.
        uri_parts = uri.split("#")
        relative_filename = uri_parts[0]
        path = os.path.normpath(os.path.join(PATH_ROOT,
                                             os.path.dirname(filename),
                                             relative_filename))
        if not os.path.exists(path):
            print_bullet("%s: Referenced file does not exist: %s" % (filename, uri))
            return False
        else:
            return True


def validate_analytics_url(filename, analytics_url):
    """
    Validate the anaylytics URL is correct. The URL is fixed format which
    includes the MD filename.

    :param filename:  The filename of the MD file containing the URI.
    :param url:  The analytics URL to validate.
    :return:  True if URL is valid and accessible
    """
    expected_url = "https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/%s?pixel" % filename
    if analytics_url != expected_url:
        print_bullet("%s: Anayltics URL is incorrect, should be %s" % (filename, expected_url))
        return False
    else:
        return True
