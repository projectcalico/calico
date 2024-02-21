import requests
import tarfile
from nose.tools import with_setup

from versions import RELEASE_VERSION

url = "https://github.com/projectcalico/calico/releases/download/{v}/release-{v}.tgz".format(
    v=RELEASE_VERSION
)

manifest_list = [
    "calico.yaml",
    "calico-etcd.yaml",
    "calico-bpf.yaml",
    "calico-typha.yaml",
    "calico-vxlan.yaml",
    "calicoctl.yaml",
    "calicoctl-etcd.yaml",
    "canal.yaml",
    "canal-etcd.yaml",
    "tigera-operator.yaml",
    "custom-resources.yaml",
]


def setup_archive():
    response = requests.get(url, stream=True)
    global file
    file = tarfile.open(fileobj=response.raw, mode="r|gz")


def teardown_archive():
    file.close()


@with_setup(setup=setup_archive, teardown=teardown_archive)
def test_manifest_present():
    for manifest in manifest_list:
        yield check_manifest_present, manifest


def check_manifest_present(manifest):
    print("[INFO] checking {} is in archive".format(manifest))
    try:
        manifest_info = file.getmember(
            "release-{v}/manifests/{m}".format(v=RELEASE_VERSION, m=manifest)
        )
        print(manifest_info.name, manifest_info.size)
        assert manifest_info.isfile()
        assert manifest_info.size > 100
    except KeyError:
        assert False, "{m} not found in archive: {url}".format(m=manifest, url=url)
