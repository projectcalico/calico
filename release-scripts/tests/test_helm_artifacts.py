import os
import yaml
import requests

#
# Note: this test is only valid for versions >= v3.18.0
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

# Helm version is the calico/node version.
version = versions[0]["components"]["calico/node"]["version"]
chart_version = versions[0]["chart"]["version"]
print("[INFO] using calico/node version for Helm artifacts: %s" % version)
print("[INFO] using chart version for Helm artifact: %s" % chart_version)


def test_calico_release_has_helm_chart():
    req = requests.head(
        "https://github.com/projectcalico/calico/releases/download/%s/tigera-operator-%s-%s.tgz"
        % (version, version, chart_version)
    )
    assert req.status_code == 302
