import os
import re

# Get the release version.
RELEASE_VERSION = os.getenv("VERSION")

# Extract release stream from the version.
match = re.search(r'(v\d+\.\d+)\.\d+', RELEASE_VERSION)
if match and len(match.groups()) == 1:
    RELEASE_STREAM = match.groups()[0]

# Get flannel version.
FLANNEL_VERSION = os.getenv("FLANNEL_VERSION")

# Get expected operator version.
OPERATOR_VERSION = os.getenv("OPERATOR_VERSION")

# Quay.io API token
QUAY_API_TOKEN = os.getenv("QUAY_API_TOKEN")

def test_variables_provided():
    assert RELEASE_VERSION
    assert RELEASE_STREAM
    assert FLANNEL_VERSION
    assert OPERATOR_VERSION
    assert QUAY_API_TOKEN
