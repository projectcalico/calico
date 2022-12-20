import requests
import tarfile

from versions import RELEASE_VERSION

urls = {
    "docs": "https://github.com/projectcalico/calico/releases/download/{v}/release-{v}.tgz".format(
        v=RELEASE_VERSION
    ),
    "github": "https://github.com/projectcalico/calico/releases/download/{v}/release-{v}.tgz".format(
        v=RELEASE_VERSION
    ),
}

manifest_list = [
    "calico.yaml",
    "calico-etcd.yaml",
    "calico-bpf.yaml",
    "calico-typha.yaml",
    "calico-vxlan.yaml",
    "calico-windows-bgp.yaml",
    "calico-windows-vxlan.yaml",
    "calicoctl.yaml",
    "calicoctl-etcd.yaml",
    "canal.yaml",
    "canal-etcd.yaml",
    "tigera-operator.yaml",
    "custom-resources.yaml",
]


def test_manifest_archive_on_release_page():
    for source, url in urls.items():
        print(
            "[INFO] checking manifests archive in {s} via {url}".format(
                s=source, url=url
            )
        )
        response = requests.get(url, stream=True)
        file = tarfile.open(fileobj=response.raw, mode="r|gz")
        for manifest in manifest_list:
            print("[INFO] checking {} is in archive".format(manifest))
            try:
                manifest_info = file.getmember(
                    "release-{v}/manifests/{m}".format(v=RELEASE_VERSION, m=manifest)
                )
                print(manifest_info.name, manifest_info.size)
                assert manifest_info.isfile()
                assert manifest_info.size > 100
            except KeyError:
                assert False, "{m} not found in archive from {s}: {url}".format(
                    m=manifest, s=source, url=url
                )
        file.close()
