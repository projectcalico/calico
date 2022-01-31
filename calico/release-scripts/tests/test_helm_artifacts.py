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
print("[INFO] using calico/node version for Helm artifacts: %s" % version)
chart_url = (
    "https://github.com/projectcalico/calico/releases/download/%s/tigera-operator-%s.tgz"
    % (version, version)
)


def test_calico_release_has_helm_chart():
    req = requests.head(chart_url)
    assert req.status_code == 302


# Note: this test is only valid for versions >= v3.19.3
def test_calico_release_in_helm_index():
    req = requests.get("https://projectcalico.docs.tigera.io/charts/index.yaml")
    assert req.status_code == 200, "Could not get helm index"
    index = yaml.safe_load(req.text)
    # Find entry
    entry = None
    for entry in index["entries"]["tigera-operator"]:
        if entry["appVersion"] == version:
            break
    assert entry is not None, "Could not find this release in helm index"
    assert entry["version"] == version, "Chart version incorrect in helm index"
    assert entry["urls"][0] == chart_url, "Chart URL incorrect in helm index"
