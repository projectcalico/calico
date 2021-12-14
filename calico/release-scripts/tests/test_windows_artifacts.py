import os
import yaml
import requests

#
# Note: this test is only valid for versions >= v3.16.0
#
DOCS_PATH = (
    "/docs"
    if os.environ.get("CALICO_DOCS_PATH") is None
    else os.environ.get("CALICO_DOCS_PATH")
)

with open("%s/_data/versions.yml" % DOCS_PATH) as f:
    versions = yaml.safe_load(f)
    RELEASE_VERSION = versions[0]["title"]
    print("[INFO] using _data/versions.yaml, discovered version: %s" % RELEASE_VERSION)

# Windows zip version is the calico/node version.
version = versions[0]["components"]["calico/node"]["version"]
print("[INFO] using calico/node version for Windows artifacts: %s" % version)


def test_node_release_has_windows_zip():
    req = requests.head(
        "https://github.com/projectcalico/node/releases/download/%s/calico-windows-%s.zip"
        % (version, version)
    )
    assert req.status_code == 302


def test_calico_release_has_windows_zip():
    req = requests.head(
        "https://github.com/projectcalico/calico/releases/download/%s/calico-windows-%s.zip"
        % (version, version)
    )
    assert req.status_code == 302
