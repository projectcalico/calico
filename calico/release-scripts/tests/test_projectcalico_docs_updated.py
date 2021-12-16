import os
from bs4 import BeautifulSoup

import requests

RELEASE_STREAM = os.environ.get("RELEASE_STREAM")


def test_http_redirects_correctly():
    req = requests.get("http://projectcalico.docs.tigera.io/latest")
    assert req.status_code == 200


def test_latest_releases_redirects_correctly():
    req = requests.get("https://projectcalico.docs.tigera.io/latest/release-notes")
    assert req.status_code == 200

    version = BeautifulSoup(req.content, features="html.parser").find("strong")
    assert version.get_text() == RELEASE_STREAM
