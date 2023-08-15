import os
import re


def get_var_or_error(var_name):
    var = os.getenv(var_name)
    if var is None:
        raise RuntimeError(f"{var_name} environment variable must be set")
    return var


# Get the release version.
RELEASE_VERSION = get_var_or_error("VERSION")

print(RELEASE_VERSION)

# Extract release stream from the version.
try:
    match = re.search(r"(v\d+\.\d+)\.\d+", RELEASE_VERSION)
    if match and len(match.groups()) == 1:
        RELEASE_STREAM = match.groups()[0]
except TypeError as exc:
    raise RuntimeError(
        f"Variable RELEASE_VERSION had bad value {RELEASE_VERSION}"
    ) from exc


# Get flannel version.
FLANNEL_VERSION = get_var_or_error("FLANNEL_VERSION")

# Get expected operator version.
OPERATOR_VERSION = get_var_or_error("OPERATOR_VERSION")

# Quay.io API token
QUAY_TOKEN = get_var_or_error("QUAY_TOKEN")


def test_variables_provided():
    assert RELEASE_VERSION
    assert RELEASE_STREAM
    assert FLANNEL_VERSION
    assert OPERATOR_VERSION
    assert QUAY_TOKEN


test_variables_provided()
