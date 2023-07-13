import re
import requests

import pytest

import variables

PPA_VER = variables.RELEASE_STREAM.replace("v", "calico-")
COMP_VER = variables.RELEASE_VERSION.replace("v", "")

UBUNTU_VERSIONS = ["bionic", "focal", "trusty", "xenial", "jammy"]

RPM_URL_TEMPL = (
    # e.g. http://binaries.projectcalico.org/rpm/calico-3.19/x86_64/calico-felix-3.19.2-1.el7.x86_64.rpm"
    
)

URL_TEMPLATES = {
    'ubuntu': {
        "felix": f"http://ppa.launchpad.net/project-calico/{PPA_VER}/ubuntu/pool/main/f/felix/",
        "networking-calico": f"http://ppa.launchpad.net/project-calico/{PPA_VER}/ubuntu/pool/main/n/networking-calico/",
    },
    'rpm': {
        "x86": f"http://binaries.projectcalico.org/rpm/{PPA_VER}/x86_64/",
        "noarch": f"http://binaries.projectcalico.org/rpm/{PPA_VER}/noarch/",
    }
}

UBUNTU_DEB_FILE_TMPL = "{component}_{component_version}-{ubuntu_version}_{arch}.deb"

RPM_FILE_TMPL = "{component}-{component_version}-1.el7.{arch}.rpm"

RPM_URLS_x86 = []
RPM_URLS_noarch = []
UBUNTU_FELIX_URLS = []
UBUNTU_NETWORKING_URLS = []

# Build a list of URLs to check for Felix packaging.
# - RPM URL
# - PPA URL for each Ubuntu version we support.
for component in ("calico-common", "calico-felix", "felix-debuginfo"):
    arch = "x86_64"
    RPM_URLS_x86.append(
        RPM_FILE_TMPL.format(
            ppa_ver=PPA_VER,
            component=component,
            component_version=COMP_VER,
            arch=arch
        )
    )

for component in ("calico-compute", "calico-control", "calico-dhcp-agent", "networking-calico"):
    arch = "noarch"
    RPM_URLS_noarch.append(
        RPM_FILE_TMPL.format(
            ppa_ver=PPA_VER,
            component=component,
            component_version=COMP_VER,
            arch=arch
        )
    )

for component in ("calico-felix", "calico-common"):
    if component == "calico-felix":
        arch = "amd64"
    else:
        arch = "all"
    for ubuntu_version in UBUNTU_VERSIONS:
        UBUNTU_FELIX_URLS.append(
            UBUNTU_DEB_FILE_TMPL.format(
                ppa_ver=PPA_VER,
                component=component,
                component_version=COMP_VER,
                ubuntu_version=ubuntu_version,
                arch=arch
            )
        )

for component in ("calico-compute", "calico-control", "calico-dhcp-agent", "networking-calico"):
    arch = "all"
    for ubuntu_version in UBUNTU_VERSIONS:
        UBUNTU_NETWORKING_URLS.append(
            UBUNTU_DEB_FILE_TMPL.format(
                ppa_ver=PPA_VER,
                component=component,
                component_version=COMP_VER,
                ubuntu_version=ubuntu_version,
                arch=arch
            )
        )


file_checks = []
file_checks += [("ubuntu", "felix", filename) for filename in UBUNTU_FELIX_URLS]
file_checks += [("ubuntu", "networking-calico", filename) for filename in UBUNTU_NETWORKING_URLS]

file_checks += [("rpm", "x86", filename) for filename in RPM_URLS_x86]
file_checks += [("rpm", "noarch", filename) for filename in RPM_URLS_noarch]

@pytest.mark.openstack
@pytest.mark.parametrize("distro,component,filename", file_checks)
def test_artifact_url(distro, component, filename):
    url_base = URL_TEMPLATES[distro][component]
    url = f"{url_base}{filename}"
    resp = requests.head(url, allow_redirects=True)
    assert resp.status_code == 200, f"Bad response from {url}"

@pytest.mark.openstack
def test_rpm_repo_avail():
    req = requests.get(f"http://binaries.projectcalico.org/rpm/{PPA_VER}")
    assert req.status_code == 200, f"PPA version {PPA_VER} not found"

@pytest.mark.openstack
def test_networking_calico_version():
    assert re.match("v", variables.RELEASE_VERSION) is not None

@pytest.mark.openstack
def test_deb_rpm_versions_match():
    regex = re.compile(f".*{variables.RELEASE_VERSION[1:4]}")
    assert regex.match(PPA_VER), f"{PPA_VER} did not match {variables.RELEASE_VERSION[1:4]}"
