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

CNI_URL_TEMPL = "https://github.com/projectcalico/{component}/releases/download/{component_version}/{binary}-{arch}"
CTL_URL_TEMPL = "https://github.com/projectcalico/{component}/releases/download/{component_version}/{binary}"

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

components = [
    {"name": "typha", "lookup": "typha", "urls": []},
    {"name": "calicoctl", "lookup": "calicoctl", "urls": []},
    {"name": "node", "lookup": "calico/node", "urls": []},
    {"name": "cni-plugin", "lookup": "calico/cni", "urls": []},
    {"name": "kube-controllers", "lookup": "calico/kube-controllers", "urls": []},
    {"name": "networking-calico", "lookup": "networking-calico", "urls": []},
    {"name": "flannel", "lookup": "flannel", "urls": []},
    {"name": "app-policy", "lookup": "calico/dikastes", "urls": []},
    {"name": "pod2daemon", "lookup": "flexvol", "urls": []},
    {"name": "calico", "lookup": "calico/node", "urls": []},
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
                component_version=versions[0]["components"][component["lookup"]][
                    "version"
                ],
            )
        )
    if component["name"] == "cni-plugin":
        for binary in ["calico", "calico-ipam"]:
            for arch in ["amd64", "arm64", "ppc64le"]:
                component["urls"].append(
                    CNI_URL_TEMPL.format(
                        component=component["name"],
                        component_version=versions[0]["components"][
                            component["lookup"]
                        ]["version"],
                        binary=binary,
                        arch=arch,
                    )
                )
    elif component["name"] == "calicoctl":
        for binary in [
            "calicoctl",
            "calicoctl-darwin-amd64",
            "calicoctl-linux-amd64",
            "calicoctl-linux-arm64",
            "calicoctl-linux-ppc64le",
            "calicoctl-windows-amd64.exe",
        ]:
            component["urls"].append(
                CTL_URL_TEMPL.format(
                    component=component["name"],
                    component_version=versions[0]["components"][component["lookup"]][
                        "version"
                    ],
                    binary=binary,
                )
            )
    elif component["name"] == "flannel":
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
    # For ease of understanding, these are the release artifacts that are tested (for release 3.6.2):
    #
    # typha:
    #     https://github.com/projectcalico/typha/releases/tag/v3.6.2
    #     https://github.com/projectcalico/typha/archive/v3.6.2.zip
    #     https://github.com/projectcalico/typha/archive/v3.6.2.tar.gz
    # node: (as typha)
    # kube-controllers: (as typha)
    # dikastes: (as typha)
    #
    # networking-calico:
    #     https://github.com/projectcalico/networking-calico/archive/v3.6.2.zip
    #     https://github.com/projectcalico/networking-calico/archive/v3.6.2.tar.gz
    #
    # cni:
    #     https://github.com/projectcalico/cni-plugin/releases/download/v3.6.2/calico-amd64
    #     https://github.com/projectcalico/cni-plugin/releases/download/v3.6.2/calico-arm64
    #     https://github.com/projectcalico/cni-plugin/releases/download/v3.6.2/calico-ppc64le
    #     https://github.com/projectcalico/cni-plugin/releases/download/v3.6.2/calico-ipam-amd64
    #     https://github.com/projectcalico/cni-plugin/releases/download/v3.6.2/calico-ipam-arm64
    #     https://github.com/projectcalico/cni-plugin/releases/download/v3.6.2/calico-ipam-ppc64le
    #     https://github.com/projectcalico/cni-plugin/archive/v3.6.2.zip
    #     https://github.com/projectcalico/cni-plugin/archive/v3.6.2.tar.gz
    #
    # calicoctl:
    #     https://github.com/projectcalico/calicoctl/releases/tag/v3.6.2
    #     https://github.com/projectcalico/calicoctl/releases/download/v3.6.2/calicoctl
    #     https://github.com/projectcalico/calicoctl/releases/download/v3.6.2/calicoctl-darwin-amd64
    #     https://github.com/projectcalico/calicoctl/releases/download/v3.6.2/calicoctl-linux-amd64
    #     https://github.com/projectcalico/calicoctl/releases/download/v3.6.2/calicoctl-linux-arm64
    #     https://github.com/projectcalico/calicoctl/releases/download/v3.6.2/calicoctl-linux-ppc64le
    #     https://github.com/projectcalico/calicoctl/releases/download/v3.6.2/calicoctl-windows-amd64.exe
    #     https://github.com/projectcalico/calicoctl/archive/v3.6.2.zip
    #     https://github.com/projectcalico/calicoctl/archive/v3.6.2.tar.gz
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
