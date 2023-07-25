#!/bin/bash

set -o errexit
set -o nounset

git config --global --add safe.directory $(pwd)
GIT_TOPLEVEL=$(git rev-parse --show-toplevel)

pip install --disable-pip-version-check --root-user-action=ignore -r ${GIT_TOPLEVEL}/hack/versions/requirements.txt
python3 ${GIT_TOPLEVEL}/hack/versions/update_versions.py
