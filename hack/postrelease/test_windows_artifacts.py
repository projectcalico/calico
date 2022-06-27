import os
import re
import requests
from versions import RELEASE_VERSION, RELEASE_STREAM

def test_calico_release_has_windows_zip():
    req = requests.head(
        "https://github.com/projectcalico/calico/releases/download/%s/calico-windows-%s.zip"
        % (RELEASE_VERSION, RELEASE_VERSION)
    )
    assert req.status_code == 302

def test_calico_windows_script_uses_expected_install_zip():
    resp = requests.get('https://projectcalico.docs.tigera.io/archive/%s/scripts/install-calico-windows.ps1' % RELEASE_STREAM)
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
