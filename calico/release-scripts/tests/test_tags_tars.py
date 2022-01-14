import os

import requests
import yaml
from parameterized import parameterized

DOCS_PATH = (
    "/docs"
    if os.environ.get("CALICO_DOCS_PATH") is None
    else os.environ.get("CALICO_DOCS_PATH")
)
RELEASE_STREAM = os.environ.get("RELEASE_STREAM")
EXCLUDED_IMAGES = ["calico/pilot-webhook", "calico/upgrade", "quay.io/coreos/flannel"]

EXPECTED_ARCHS = ["amd64", "arm64", "ppc64le"]

with open("%s/_data/versions.yml" % DOCS_PATH) as f:
    versions = yaml.safe_load(f)
    RELEASE_VERSION = versions[0]["title"]
    print("[INFO] using _data/versions.yaml, discovered version: %s" % RELEASE_VERSION)

TAG_URL_TEMPL = (
    "https://github.com/projectcalico/{component}/releases/tag/{component_version}"
)
ZIP_URL_TEMPL = (
    "https://github.com/projectcalico/{component}/archive/{component_version}.zip"
)
TAR_URL_TEMPL = (
    "https://github.com/projectcalico/{component}/archive/{component_version}.tar.gz"
)

FLANNEL_TAG_URL_TEMPL = (
    "https://github.com/coreos/{component}/releases/tag/{component_version}"
)
FLANNEL_ZIP_URL_TEMPL = (
    "https://github.com/coreos/{component}/archive/{component_version}.zip"
)
FLANNEL_TAR_URL_TEMPL = (
    "https://github.com/coreos/{component}/archive/{component_version}.tar.gz"
)

DOCS_TAR_URL_TEMPL = (
    "https://github.com/projectcalico/{component}/releases/download/"
    "{component_version}/release-{component_version}.tgz"
)

CTL_URL_TEMPL = "https://github.com/projectcalico/calico/releases/download/{component_version}/{binary}"

components = [
    {"name": "flannel", "lookup": "flannel", "urls": []},
    {"name": "calico", "lookup": "calico/node", "urls": []},
]

calicoctl_binaries = [
    "calicoctl-darwin-amd64",
    "calicoctl-linux-amd64",
    "calicoctl-linux-arm64",
    "calicoctl-linux-ppc64le",
    "calicoctl-windows-amd64.exe",
]

for component in components:
    component["urls"] = [
        TAG_URL_TEMPL.format(
            component=component["name"],
            component_version=versions[0]["components"][component["lookup"]]["version"],
        ),
        ZIP_URL_TEMPL.format(
            component=component["name"],
            component_version=versions[0]["components"][component["lookup"]]["version"],
        ),
        TAR_URL_TEMPL.format(
            component=component["name"],
            component_version=versions[0]["components"][component["lookup"]]["version"],
        ),
    ]
    if component["name"] == "calico":
        component["urls"].append(
            DOCS_TAR_URL_TEMPL.format(
                component=component["name"],
                component_version=RELEASE_VERSION,
            )
        )
        for binary in calicoctl_binaries:
            component["urls"].append(
                CTL_URL_TEMPL.format(
                    component_version=RELEASE_VERSION,
                    binary=binary,
                )
            )
    if component["name"] == "flannel":
        component["urls"] = [
            FLANNEL_TAG_URL_TEMPL.format(
                component=component["name"],
                component_version=versions[0]["components"][component["lookup"]][
                    "version"
                ],
            ),
            FLANNEL_ZIP_URL_TEMPL.format(
                component=component["name"],
                component_version=versions[0]["components"][component["lookup"]][
                    "version"
                ],
            ),
            FLANNEL_TAR_URL_TEMPL.format(
                component=component["name"],
                component_version=versions[0]["components"][component["lookup"]][
                    "version"
                ],
            ),
        ]
    # The intent of all the above looping and lookups is to generate a list of component URLs that must be present.
    # We then pass that list of URLs into the simple test below (which gets the URL
    # and asserts that the response code is 200)
    #
    # For ease of understanding, these are the release artifacts that are tested (for release 3.21.3):
    #
    # flannel:
    #     https://github.com/coreos/flannel/releases/download/v0.9.1/flannel-v0.9.1-linux-amd64.tar.gz

unrolled_urls = []
for component in components:
    for url in component["urls"]:
        unrolled_urls.append(url)


@parameterized(unrolled_urls)
def test_artifact_url(url):
    resp = requests.get(url, stream=True)
    print("[INFO] %s: %s" % (resp.status_code, url))
    assert resp.status_code == 200
