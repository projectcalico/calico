import os
import pickle
import re
import shutil
import sys
import textwrap
import urllib2

# The root directory
PATH_ROOT = os.path.dirname(os.path.dirname(os.path.realpath("__file_")))

# Path names relative to the root of the project
PATH_CALICOCTL_REQS = os.path.join("calicoctl", "requirements.txt")
PATH_CALICOCTL_NODE = os.path.join("calicoctl", "calico_ctl", "node.py")
PATH_CALICOCTL_INIT = os.path.join("calicoctl", "calico_ctl", "__init__.py")
PATH_CALICONODE_BUILD = os.path.join("calico_node", "build.sh")
PATH_MAIN_README = "README.md"
PATH_DOCS = "docs"
PATH_RELEASE_DATA = ".releasedata"
PATH_BUILDING = os.path.join(PATH_DOCS, "Building.md")

# Regexes for calico-docker version format.
INIT_VERSION = re.compile(r'__version__\s*=\s*"(.*)"')
VERSION_RE = re.compile(r'^v(\d+)\.(\d+)\.(\d+)$')
VERSION_NAME_RE = re.compile(r'^v(\d+)\.(\d+)\.(\d+)[.-](\w+)$')

# Files to include in the list of files to automatically update.  All file
# paths are relative to the project root.
UPDATE_FILES_STATIC = [PATH_MAIN_README,
                       PATH_CALICOCTL_NODE,
                       PATH_CALICOCTL_REQS,
                       PATH_CALICONODE_BUILD,
                       PATH_CALICOCTL_INIT]
UPDATE_FILES_DIRS = [PATH_DOCS]
UPDATE_FILES_EXCLUDE = [PATH_BUILDING]
UPDATE_FILES_RE = re.compile("(.*\.md)|(Vagrantfile)|(user\-data\-.*)")

# Indicators separating blocks of master only and release only text.
BLOCK_INDICATOR_MASTER_START = "<!--- master only -->"
BLOCK_INDICATOR_MASTER_ELSE = "<!--- else"
BLOCK_INDICATOR_MASTER_END = "<!--- end of master only -->"


def get_update_file_list():
    """
    Return a set of files that need to be updated with new version strings.
    :return: A set of files that need to be updated with release information.
    """
    update_files_list = set(UPDATE_FILES_STATIC)
    update_files_exclude = set(UPDATE_FILES_EXCLUDE)
    for dirn in UPDATE_FILES_DIRS:
        for root, dirs, files in os.walk(os.path.join(PATH_ROOT, dirn)):
            for filen in files:
                if UPDATE_FILES_RE.match(filen):
                    filep = os.path.join(root, filen)
                    update_files_list.add(os.path.relpath(filep, PATH_ROOT))
    return update_files_list - update_files_exclude


def replace_file(filename, contents):
    """
    Perform a safe update of the file, keeping a backup until the new file has
    been written.  File mode is transferred to the new file.

    :param filename: The name of the file (relative to project root)
    :param contents: The contents of the files as a list of lines, each line
    should include the newline character.
    """
    filename = os.path.join(PATH_ROOT, filename)
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
    with open(os.path.join(PATH_ROOT, filename), "r") as in_file:
        return in_file.readlines()


def get_calicoctl_version():
    """
    Determine the current version from the calicoctl __init__.py
    :return: The current calicoctl version
    """
    for line in load_file(PATH_CALICOCTL_INIT):
        match = INIT_VERSION.match(line.strip())
        if match:
            # The python version string does not include the "v", so add it in.
            return "v" + match.group(1)
    print_paragraph("Unable to locate version string in %s" % PATH_CALICOCTL_INIT)
    sys.exit(1)


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
    filen = os.path.join(PATH_ROOT, PATH_RELEASE_DATA)
    try:
        with open(filen, "r") as in_file:
            data = pickle.load(in_file)

        if data:
            print_warning("You are continuing an existing release.  If this "
                          "an error, delete the release data file and try "
                          "again.  "
                          "Filename = %s" % filen)

        return data
    except:
        return {}

def save_release_data(release_data):
    """
    Save the release data.
    :param release_data: The release data to pickle.
    """
    assert isinstance(release_data, dict)
    filen = os.path.join(PATH_ROOT, PATH_RELEASE_DATA)
    filen_bak = "%s.bak" % filen
    try:
        if os.path.exists(filen_bak):
            print_warning("Backup release data is found indicating an unclean "
                          "save.  If this is expected, delete the file and "
                          "try again.  "
                          "Filename=%s" % filen_bak)
            sys.exit(1)

        if os.path.exists(filen):
            os.rename(filen, filen_bak)

        with open(filen, "w") as out_file:
            pickle.dump(release_data, out_file)

        if os.path.exists(filen_bak):
            os.remove(filen_bak)
    except Exception, e:
        print_warning("Unable to store release data: %s" % e)
        sys.exit(1)


def get_github_library_version(name, url):
    """
    Ask the user for the version of a GitHub library.
    :param name: A friendly name.
    :param url: The GitHub repo.
    :return:
    """
    while True:
        version = raw_input("Version of %s ?: " % name)
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
    try:
        urllib2.urlopen(url)
        return True
    except urllib2.HTTPError, e:
        return False
    except urllib2.URLError, e:
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
