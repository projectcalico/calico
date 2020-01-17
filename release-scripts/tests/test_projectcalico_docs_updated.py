import os
from bs4 import BeautifulSoup

import requests

RELEASE_STREAM = os.environ.get('RELEASE_STREAM')


def test_http_redirects_correctly():
    req = requests.get("http://docs.projectcalico.org/latest")
    assert req.status_code == 200


def test_latest_redirects_correctly():
    req = requests.get("https://docs.projectcalico.org/latest")
    assert req.status_code == 200

    redirect = BeautifulSoup(req.content, features="html.parser").find('a', href=True)
    assert redirect['href'] == "https://docs.projectcalico.org/%s/" % RELEASE_STREAM


def test_latest_releases_redirects_correctly():
    req = requests.get("https://docs.projectcalico.org/latest/release-notes")
    assert req.status_code == 200

    redirect = BeautifulSoup(req.content, features="html.parser").find('a', href=True)
    assert redirect['href'] == "https://docs.projectcalico.org/%s/release-notes/" % RELEASE_STREAM
