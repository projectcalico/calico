#!/usr/bin/env python

import os
import re

VERSION_MASK = "__version__"


def split_version(f):
    m = re.match("(master|v[0-9]+\\.[0-9]+)/", f)
    if m:
        return m.group(1), f[:m.start(1)] + VERSION_MASK + f[m.end(1):-3]
    return None, f[:-3]


def version_later_than(v1, v2):
    # Basic implementation for now.  Improve if we ever go past v9.Y
    # or vX.9!
    return v1 > v2


if __name__ == "__main__":
    # Find all the .md files.
    md_files = []
    for root, _, files in os.walk("."):
        md_files = md_files + [os.path.join(root, f)[2:]
                               for f in filter(lambda fn: fn.endswith(".md"),
                                               files)]
    # Process all file names to find the latest available version for
    # each version-masked path.
    masked_to_latest_version = {}
    for f in md_files:
        version, masked = split_version(f)
        if version:
            latest_version = masked_to_latest_version.get(masked)
            if latest_version and version_later_than(latest_version, version):
                pass
            else:
                masked_to_latest_version[masked] = version

    # For each file, replace its canonical URL with that of the latest
    # available version for that file's path.
    for f in md_files:
        version, masked = split_version(f)
        latest_version = masked_to_latest_version.get(masked)
        if latest_version:
            path = os.path.abspath(f)
            replacement = "canonical_url: 'https://docs.projectcalico.org/%s'" % (masked.replace(VERSION_MASK, latest_version))
            lines = []
            with open(path, "r") as file:
                lines = file.readlines()
                file.close
            with open(path, "w") as file:
                for line in lines:
                    file.write(re.sub(r'^canonical_url: .*', replacement, line))
                file.close()
