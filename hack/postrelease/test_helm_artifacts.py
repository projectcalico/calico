import os
import yaml
import requests
from versions import RELEASE_VERSION


def test_calico_release_has_helm_chart():
    chart_url = (
        "https://github.com/projectcalico/calico/releases/download/%s/tigera-operator-%s.tgz"
        % (RELEASE_VERSION, RELEASE_VERSION)
    )

    req = requests.head(chart_url)
    assert req.status_code == 302


def test_calico_release_in_helm_index():
    chart_url = (
        "https://github.com/projectcalico/calico/releases/download/%s/tigera-operator-%s.tgz"
        % (RELEASE_VERSION, RELEASE_VERSION)
    )

    req = requests.get("https://projectcalico.docs.tigera.io/charts/index.yaml")
    assert req.status_code == 200, "Could not get helm index"
    index = yaml.safe_load(req.text)
    # Find entry
    entry = None
    for entry in index["entries"]["tigera-operator"]:
        if entry["appVersion"] == RELEASE_VERSION:
            break
    assert entry is not None, "Could not find this release in helm index"
    assert entry["version"] == RELEASE_VERSION, "Chart version (%s) incorrect in helm index" % (entry["version"])
    assert entry["urls"][0] == chart_url, "Chart URL (%s) incorrect in helm index" % (entry["urls"][0])
