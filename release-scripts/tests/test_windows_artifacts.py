import os
import requests
from bs4 import BeautifulSoup

req = requests.get("https://docs.projectcalico.org/release-notes/")
soup = BeautifulSoup(req.content, "html.parser")
version = soup.find("td", text="calico/node").find_next_sibling().text
assert version != ""

def test_node_release_has_windows_zip():
    req = requests.head("https://github.com/projectcalico/node/releases/download/%s/calico-windows-%s.zip" % (version, version))
    assert req.status_code == 302

def test_calico_release_has_windows_zip():
    req = requests.head("https://github.com/projectcalico/calico/releases/download/%s/calico-windows-%s.zip" % (version, version))
    assert req.status_code == 302
