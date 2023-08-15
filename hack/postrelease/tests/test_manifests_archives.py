import os
import tarfile

import pytest
import utilities
import variables

release_filename = f"release-{variables.RELEASE_VERSION}.tgz"
url = f"https://github.com/projectcalico/calico/releases/download/{variables.RELEASE_VERSION}/{release_filename}"

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

OVERRIDE_FILE = os.getenv("OVERRIDE_FILE")


@pytest.fixture(scope="session")
def image_file_members(tmpdir_factory):
    if OVERRIDE_FILE:
        tf_filename = OVERRIDE_FILE
    else:
        tmpfile_name = tmpdir_factory.mktemp("data").join(release_filename)
        utilities.download_url_to_file(url, tmpfile_name)
        tf_filename = tmpfile_name
    with tarfile.open(tf_filename, "r|gz") as manifest_tarfile:
        tarfile_members = utilities.tarfile_members_to_map(manifest_tarfile)
    return tarfile_members


@pytest.mark.slow
@pytest.mark.github
@pytest.mark.tryfirst
@pytest.mark.parametrize("manifest", manifest_list)
def test_manifest_present(image_file_members, manifest):
    """
    Validate that the given manifest is in the given archive
    """
    try:
        manifest_path = f"release-{variables.RELEASE_VERSION}/manifests/{manifest}"
        manifest_info = image_file_members[manifest_path]
        if not manifest_info.isfile():
            raise AssertionError(f"Manifest entry {manifest_path} is not a file")
        if manifest_info.size < 100:
            raise AssertionError(
                f"Manifest entry {manifest_path} size is < 100 bytes ({manifest_info.size} bytes found)"
            )
    except KeyError:
        raise AssertionError(f"{manifest} not found in archive: {url}")
