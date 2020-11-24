import os

import re
import requests
import yaml

DOCS_PATH = os.environ.get("CALICO_DOCS_PATH") or "/docs"
RELEASE_STREAM = os.environ.get("RELEASE_STREAM")
PPA_VER = RELEASE_STREAM.replace("v", "calico-")

with open("%s/_data/versions.yml" % DOCS_PATH) as f:
    versions = yaml.safe_load(f)
    NETWORKING_VER = versions[0]["components"]["networking-calico"]["version"]
    print("[INFO] using ppa version: %s" % PPA_VER)
    print("[INFO] using networking-calico version: %s" % NETWORKING_VER)


def test_rpm_repo_avail():
    req = requests.get("http://binaries.projectcalico.org/rpm/%s" % PPA_VER)
    assert req.status_code == 200


def test_networking_calico_version():
    assert re.match("v", NETWORKING_VER) is not None


def test_deb_rpm_versions_match():
    regex = re.compile(".*%s" % NETWORKING_VER[1:4])
    assert regex.match(PPA_VER), "%s did not match %s" % (PPA_VER, NETWORKING_VER[1:4])


def test_networking_calico_tag_avail():
    req = requests.get(
        "https://github.com/projectcalico/networking-calico/releases/tag/%s"
        % NETWORKING_VER
    )
    assert req.status_code == 200
