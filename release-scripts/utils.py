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
__version__ = "0.22.0-dev"

# Path names relative to the root of the project
PATH_MAIN_README = "README.md"
PATH_DOCS = "v1.6"
PATH_RELEASE_DATA = ".releasedata"

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
UPDATE_FILES_STATIC = [PATH_MAIN_README]
UPDATE_FILES_DIRS = [PATH_DOCS]
UPDATE_FILES_EXCLUDE = []
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

def get_github_library_version(name, url):
    """
    Ask the user for the version of a GitHub library.
    :param name: A friendly name.
    :param url: The GitHub repo.
    :return:
    """
    while True:
        # For the release, make sure the default versions do not include "-dev"
        version = raw_input("Version of %s?: " % name)
        if not url_exists("%s/releases/tag/%s" % (url, version)):
            print_warning("The version of %s is not valid.  Ensure you've chosen a correct value by checking the "
                          "GitHub releases for exact naming at "
                          "%s/releases before you continue." % (name, url))
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
