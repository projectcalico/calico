import os
import yaml
import requests

DOCS_PATH = (
    "/docs"
    if os.environ.get("CALICO_DOCS_PATH") is None
    else os.environ.get("CALICO_DOCS_PATH")
)

with open("%s/_data/versions.yml" % DOCS_PATH) as f:
    versions = yaml.safe_load(f)
    RELEASE_VERSION = versions[0]["title"]
    print("[INFO] using _data/versions.yaml, discovered version: %s" % RELEASE_VERSION)

def test_calico_release_has_windows_zip():
    req = requests.head(
        "https://github.com/projectcalico/calico/releases/download/%s/calico-windows-%s.zip"
        % (RELEASE_VERSION, RELEASE_VERSION)
    )
    assert req.status_code == 302
