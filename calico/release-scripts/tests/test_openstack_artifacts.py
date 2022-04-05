import os

import re
import requests
import yaml
from parameterized import parameterized

DOCS_PATH = os.environ.get("CALICO_DOCS_PATH") or "/docs"
RELEASE_STREAM = os.environ.get("RELEASE_STREAM")
PPA_VER = RELEASE_STREAM.replace("v", "calico-")
UBUNTU_VERSIONS = ["bionic", "focal", "trusty", "xenial"]
components = ["felix"]
PPA_IMAGE_URL_TEMPL = (
    # e.g. http://ppa.launchpad.net/project-calico/calico-3.19/ubuntu/pool/main/f/felix/calico-felix_3.19.2-focal_amd64.deb
    "http://ppa.launchpad.net/project-calico/{ppa_ver}/ubuntu/pool/main/f/felix/calico-{component}_{component_version}-{ubuntu_version}_amd64.deb"
)
RPM_URL_TEMPL = (
    # e.g. http://binaries.projectcalico.org/rpm/calico-3.19/x86_64/calico-felix-3.19.2-1.el7.x86_64.rpm"
    "http://binaries.projectcalico.org/rpm/{ppa_ver}/x86_64/calico-{component}-{component_version}-1.el7.x86_64.rpm"
)

unrolled_urls = []
with open("%s/_data/versions.yml" % DOCS_PATH) as f:
    versions = yaml.safe_load(f)
for component in components:
    unrolled_urls.append(
        RPM_URL_TEMPL.format(
            ppa_ver=PPA_VER,
            component=component,
            component_version=versions[0]["components"]["calico/node"][
                "version"
            ].replace("v", ""),
        )
    )
    for UBUNTU_VERSION in UBUNTU_VERSIONS:
        unrolled_urls.append(
            PPA_IMAGE_URL_TEMPL.format(
                ppa_ver=PPA_VER,
                component=component,
                component_version=versions[0]["components"]["calico/node"][
                    "version"
                ].replace("v", ""),
                ubuntu_version=UBUNTU_VERSION,
            )
        )


@parameterized(unrolled_urls)
def test_artifact_url(url):
    resp = requests.get(url, stream=True)
    print("[INFO] %s: %s" % (resp.status_code, url))
    assert resp.status_code == 200


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
