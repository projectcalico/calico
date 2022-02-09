import os
import re
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

    match = re.search(r'(v[0-9]+\.[0-9]+)\..+', RELEASE_VERSION)
    if match and len(match.groups()) == 1:
        MAJOR_MINOR_VERSION = match.groups()[0]
    assert MAJOR_MINOR_VERSION != ""

    print("[INFO] using _data/versions.yaml, discovered version: %s, major.minor version: %s" % (RELEASE_VERSION, MAJOR_MINOR_VERSION))

def test_calico_release_has_windows_zip():
    req = requests.head(
        "https://github.com/projectcalico/calico/releases/download/%s/calico-windows-%s.zip"
        % (RELEASE_VERSION, RELEASE_VERSION)
    )
    assert req.status_code == 302

def test_calico_windows_script_uses_expected_install_zip():
    resp = requests.get('https://projectcalico.docs.tigera.io/archive/%s/scripts/install-calico-windows.ps1' % MAJOR_MINOR_VERSION)
    lines = resp.text.split('\n')
    # Go through install-calico-windows.ps1 and extract the powershell variables
    # used to download the corresponding calico-windows.zip file.
    for line in lines:
        # ReleaseBaseURL looks like 'https://github.com/projectcalico/calico/releases/download/v3.21.4/'
        if '$ReleaseBaseURL=' in line:
            match = re.search(r'\$ReleaseBaseURL="(.*)",$', line)
            if match and len(match.groups()) == 1:
                base_url = match.groups()[0]
        # ReleaseFile looks like 'calico-windows-v3.21.4.zip'
        if '$ReleaseFile=' in line:
            match = re.search(r'\$ReleaseFile="(.*)",$', line)
            if match and len(match.groups()) == 1:
                release_file = match.groups()[0]

    assert base_url != "" and release_file != ""

    resp = requests.head(base_url + release_file)
    assert resp.status_code == 302
