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
  do_release.py [--new-version=<VERSION>]

Options:
  -h --help     Show this screen.

"""
import os
import shutil

from docopt import docopt


def release():
    new_version = arguments.get("--new-version")
    if not new_version:
        new_version = raw_input("New Calico version? (vX.Y): ")

    # Check if any of the new version dirs exist already
    new_dirs = ["./%s" % new_version,
            "./_data/%s" % new_version,
            "./_layouts/%s" % new_version]
    for new_dir in new_dirs:
        if os.path.isdir(new_dir):
            # Quit instead of making assumptions.
            print("A versioned folder for %s already exists. Remove and rerun this script?" % new_dir)

    # Create the versioned directories.
    shutil.copytree("./master", new_version)

    # Temporary workdown, use vX_Y instead of vX.Y
    # https://github.com/jekyll/jekyll/issues/5429 - Fixed in Jekyll 3.3
    shutil.copytree("./_data/master", "./_data/%s" % new_version.replace(".", "_"))
    shutil.copytree("./_includes/master", "./_includes/%s" % new_version, symlinks=True)

if __name__ == "__main__":
    arguments = docopt(__doc__)
    release()
