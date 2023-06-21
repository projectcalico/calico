import re
import requests

import variables

def test_calico_release_has_windows_zip():
    req = requests.head(
        "https://github.com/projectcalico/calico/releases/download/%s/calico-windows-%s.zip"
        % (variables.RELEASE_VERSION, variables.RELEASE_VERSION)
    )
    assert req.status_code == 302

def test_calico_windows_script_uses_expected_install_zip():
    resp = requests.get('https://github.com/projectcalico/calico/releases/download/%s/install-calico-windows.ps1' % variables.RELEASE_VERSION)
    base_url = re.search(r'\$ReleaseBaseURL="(.*)",', resp.text).group(1)
    release_file = re.search(r'\$ReleaseFile="(.*)",', resp.text).group(1)

    print base_url + release_file

    assert base_url != "" and release_file != ""

    resp = requests.head(base_url + release_file)
    assert resp.status_code == 302
