import os
import requests

assert os.environ.get('VERSION')
version = os.environ.get('VERSION')

def test_node_release_has_windows_zip():
    req = requests.head("https://github.com/projectcalico/node/releases/download/%s/calico-windows-%s.zip" % (version, version))
    assert req.status_code == 302

def test_calico_release_has_windows_zip():
    req = requests.head("https://github.com/projectcalico/calico/releases/download/%s/calico-windows-%s.zip" % (version, version))
    assert req.status_code == 302
