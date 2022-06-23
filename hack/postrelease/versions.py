import os
import re

# Get the release version.
RELEASE_VERSION = os.getenv("VERSION")

# Extract release stream from the version.
match = re.search(r'(v[0-9]+\.[0-9]+)\..+', RELEASE_VERSION)
if match and len(match.groups()) == 1:
    RELEASE_STREAM = match.groups()[0]

# Get flannel version.
FLANNEL_VERSION = os.getenv("FLANNEL_VERSION")

# Get expected operator version.
OPERATOR_VERSION = os.getenv("OPERATOR_VERSION")

# Expected VPP version.
VPP_VERSION = os.getenv("VPP_VERSION")

def test_versions_provided():
    assert RELEASE_VERSION != ""
    assert RELEASE_STREAM != ""
    assert FLANNEL_VERSION != ""
    assert OPERATOR_VERSION != ""
    assert VPP_VERSION != ""
