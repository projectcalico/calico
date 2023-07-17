import re

import pytest
import requests

import variables

DOWNLOAD_BASE = "https://github.com/projectcalico/calico/releases/download"

WINDOWS_RELEASE_BASE_URL = f"{DOWNLOAD_BASE}/{variables.RELEASE_VERSION}/"
WINDOWS_RELEASE_FILE = f"calico-windows-{variables.RELEASE_VERSION}.zip"

# Expected calicoctl binaries.
calicoctl_binaries = [
    "calicoctl-darwin-amd64",
    "calicoctl-darwin-arm64",
    "calicoctl-linux-amd64",
    "calicoctl-linux-arm64",
    "calicoctl-linux-armv7",
    "calicoctl-linux-ppc64le",
    "calicoctl-linux-s390x",
    "calicoctl-windows-amd64.exe",
    "install-calico-windows.ps1",
    "SHA256SUMS",
    "metadata.yaml",
    "ocp.tgz",
    f"calico-windows-{variables.RELEASE_VERSION}.zip",
    f"tigera-operator-{variables.RELEASE_VERSION}.tgz",
    f"release-{variables.RELEASE_VERSION}.tgz",
]

# Build out the expected URLs for a Calico release.
project_tags = (
    ("projectcalico/calico", variables.RELEASE_VERSION),
    ("coreos/flannel", variables.FLANNEL_VERSION),
)


@pytest.mark.github
@pytest.mark.parametrize("artifact", calicoctl_binaries)
def test_calico_release_downloads(artifact):
    url = f"https://github.com/projectcalico/calico/releases/download/{variables.RELEASE_VERSION}/{artifact}"
    resp = requests.head(url, allow_redirects=True)
    assert resp.status_code == 200


@pytest.mark.github
@pytest.mark.parametrize("project,release", project_tags)
def test_release_archives(project, release):
    for format in ("zip", "tar.gz"):
        url = f"https://github.com/{project}/archive/{release}.{format}"
        resp = requests.head(url, allow_redirects=True)
        assert resp.status_code == 200


@pytest.mark.github
@pytest.mark.parametrize("project,tagname", project_tags)
def test_project_tag(project, tagname):
    url = f"https://github.com/{project}/releases/tag/{tagname}"
    resp = requests.head(url, allow_redirects=True)
    assert resp.status_code == 200


@pytest.mark.github
@pytest.mark.windows
def test_windows_install_release():
    url = f"https://github.com/projectcalico/calico/releases/download/{variables.RELEASE_VERSION}/install-calico-windows.ps1"
    resp = requests.get(url)
    base_url = re.search(r'\$ReleaseBaseURL="(.*)",', resp.text).group(1)
    release_file = re.search(r'\$ReleaseFile="(.*)",', resp.text).group(1)

    assert base_url == WINDOWS_RELEASE_BASE_URL
    assert release_file == WINDOWS_RELEASE_FILE

    resp = requests.head(f"{base_url}{release_file}", allow_redirects=True)
    assert resp.status_code == 200
