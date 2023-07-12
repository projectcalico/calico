import re
import requests
from parameterized import parameterized

import variables

PPA_VER = variables.RELEASE_STREAM.replace("v", "calico-")
UBUNTU_VERSIONS = ["bionic", "focal", "trusty", "xenial"]
PPA_IMAGE_URL_TEMPL = (
    # e.g. http://ppa.launchpad.net/project-calico/calico-3.19/ubuntu/pool/main/f/felix/calico-felix_3.19.2-focal_amd64.deb
    "http://ppa.launchpad.net/project-calico/{ppa_ver}/ubuntu/pool/main/f/felix/calico-{component}_{component_version}-{ubuntu_version}_amd64.deb"
)
RPM_URL_TEMPL = (
    # e.g. http://binaries.projectcalico.org/rpm/calico-3.19/x86_64/calico-felix-3.19.2-1.el7.x86_64.rpm"
    "http://binaries.projectcalico.org/rpm/{ppa_ver}/x86_64/calico-{component}-{component_version}-1.el7.x86_64.rpm"
)

URLS = []

# Build a list of URLs to check for Felix packaging.
# - RPM URL
# - PPA URL for each Ubuntu version we support.
for component in ["felix"]:
    URLS.append(
        RPM_URL_TEMPL.format(
            ppa_ver=PPA_VER,
            component=component,
            component_version=variables.RELEASE_VERSION.replace("v", ""),
        )
    )

    for UBUNTU_VERSION in UBUNTU_VERSIONS:
        URLS.append(
            PPA_IMAGE_URL_TEMPL.format(
                ppa_ver=PPA_VER,
                component=component,
                component_version=variables.RELEASE_VERSION.replace("v", ""),
                ubuntu_version=UBUNTU_VERSION,
            )
        )


@parameterized(URLS)
def test_artifact_url(url):
    resp = requests.get(url, stream=True)
    print("[INFO] %s: %s" % (resp.status_code, url))
    assert resp.status_code == 200, "Bad response from %s" % url


def test_rpm_repo_avail():
    req = requests.get("http://binaries.projectcalico.org/rpm/%s" % PPA_VER)
    assert req.status_code == 200, "PPA version %s not found" % PPA_VER


def test_networking_calico_version():
    assert re.match("v", variables.RELEASE_VERSION) is not None


def test_deb_rpm_versions_match():
    regex = re.compile(".*%s" % variables.RELEASE_VERSION[1:4])
    assert regex.match(PPA_VER), "%s did not match %s" % (PPA_VER, variables.RELEASE_VERSION[1:4])
