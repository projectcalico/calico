import os

import re
import requests
import yaml

DOCS_PATH = os.environ.get("CALICO_DOCS_PATH") or "/docs"
RELEASE_STREAM = os.environ.get("RELEASE_STREAM")
PPA_VER = RELEASE_STREAM.replace("v", "calico-")

with open("%s/_data/versions.yml" % DOCS_PATH) as f:
    versions = yaml.safe_load(f)
    NETWORKING_VER = versions[0]['components']['networking-calico']['version']
    print("[INFO] using ppa version: %s" % PPA_VER)
    print("[INFO] using networking-calico version: %s" % NETWORKING_VER)


def test_networking_calico_version():
    # Check that NETWORKING_VER starts with a 'v'
    # (note that this is true only since the move of networking-calico to github)
    assert NETWORKING_VER.startswith("v")


def test_rpm_repo_avail():
    req = requests.get("http://binaries.projectcalico.org/rpm/%s" % PPA_VER)
    assert req.status_code == 200


def test_deb_repo_avail():
    req = requests.get("http://ppa.launchpad.net/project-calico/%s/" % PPA_VER)
    assert req.status_code == 200


def test_rpm_package_present():
    regex = re.compile(".*%s.*rpm" % NETWORKING_VER[1:])
    res = requests.get("http://binaries.projectcalico.org/rpm/%s/x86_64/" % PPA_VER)
    assert re.search(regex, res.text), (
        "binaries.projectcalico.org did not have rpm with version %s"
        % (NETWORKING_VER[1:])
    )


def test_deb_package_present():
    regex = re.compile(".*%s.*deb" % NETWORKING_VER[1:])
    res = requests.get(
        "http://ppa.launchpad.net/project-calico/%s/ubuntu/pool/main/n/networking-calico/"
        % PPA_VER
    )
    assert re.search(
        regex, res.text
    ), "ppa.launchpad.net did not have deb with version %s" % (NETWORKING_VER[1:])


def test_networking_calico_tag_avail():
    req = requests.get(
        "https://github.com/projectcalico/networking-calico/releases/tag/%s"
        % NETWORKING_VER
    )
    assert req.status_code == 200
