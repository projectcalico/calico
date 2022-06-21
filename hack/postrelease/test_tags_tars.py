import os
import requests
import yaml
from parameterized import parameterized
from versions import RELEASE_VERSION, FLANNEL_VERSION

# Expected calicoctl binaries.
calicoctl_binaries = [
    "calicoctl-darwin-amd64",
    "calicoctl-linux-amd64",
    "calicoctl-linux-arm64",
    "calicoctl-linux-ppc64le",
    "calicoctl-windows-amd64.exe",
]

# Build out the expected URLs for a Calico release.
calico = {
    "name": "calico",
    "urls": [
        "https://github.com/projectcalico/calico/releases/tag/{v}".format(v=RELEASE_VERSION),
        "https://github.com/projectcalico/calico/archive/{v}.zip".format(v=RELEASE_VERSION),
        "https://github.com/projectcalico/calico/archive/{v}.tar.gz".format(v=RELEASE_VERSION),
        "https://github.com/projectcalico/calico/releases/download/{v}/release-{v}.tgz".format(v=RELEASE_VERSION),
    ]
}

# Add in calicoctl URLs.
CTL_URL_TEMPL = "https://github.com/projectcalico/calico/releases/download/{v}/{binary}"
for binary in calicoctl_binaries:
    calico["urls"].append(CTL_URL_TEMPL.format(v=RELEASE_VERSION, binary=binary))


# Build out expected URLs for flannel.
flannel = {
    "name": "flannel", 
    "urls": [
        "https://github.com/coreos/flannel/releases/tag/{v}".format(v=FLANNEL_VERSION),
        "https://github.com/coreos/flannel/archive/{v}.zip".format(v=FLANNEL_VERSION),
        "https://github.com/coreos/flannel/archive/{v}.tar.gz".format(v=FLANNEL_VERSION),
    ],
}

# The intent of all the above is to generate a list of component URLs that must be present.
# We then pass that list of URLs into the simple test below (which gets the URL
# and asserts that the response code is 200)
unrolled_urls = []
for component in [flannel, calico]:
    for url in component["urls"]:
        unrolled_urls.append(url)

@parameterized(unrolled_urls)
def test_artifact_url(url):
    resp = requests.get(url, stream=True)
    print("[INFO] %s: %s" % (resp.status_code, url))
    assert resp.status_code == 200
