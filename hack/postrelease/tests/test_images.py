import json
import subprocess

import docker
import pytest
import requests
import variables

OPERATOR_IMAGE = f"quay.io/tigera/operator:{variables.OPERATOR_VERSION}"

# Architectures we expect to be present in multi-arch image manifests.
EXPECTED_ARCHS = ["amd64", "arm64", "ppc64le", "s390x"]

# Those same architectures in Docker's arch format
DOCKER_ARCHS = ['linux/amd64', 'linux/arm64', 'linux/ppc64le', 'linux/s390x']


# Images we expect to exist as part of a Calico release, without
# a registry assigned.
EXPECTED_IMAGES = [
    "calico/apiserver",
    "calico/cni",
    "calico/csi",
    "calico/dikastes",
    "calico/flannel-migration-controller",
    "calico/kube-controllers",
    "calico/node",
    "calico/typha",
]

IMAGES_NO_FIPS = [
    'calico/ctl',
    'calico/key-cert-provisioner',
    "calico/pod2daemon-flexvol",
]

EXPECTED_WINDOWS_IMAGES = [
    "calico/cni-windows",
    "calico/node-windows",
]

TAG_SUFFIXES = [
    "amd64",
    "arm64",
    "ppc64le",
    "s390x",
]

FIPS_TAG_SUFFIXES = [
    "fips-amd64",
    "fips",
]


# Images that we exclude from the assertions below.
EXCLUDED_IMAGES = []
OPERATOR_EXCLUDED_IMAGES = EXCLUDED_IMAGES + [
    "calico/csi",
    "calico/ctl",
    "calico/dikastes",
    "calico/flannel-migration-controller",
    "calico/windows",
]

CHECK_IMAGES = [f"{img}:{variables.RELEASE_VERSION}" for img in EXPECTED_IMAGES if img not in EXCLUDED_IMAGES]

# Images that we expect to be published to GCR.
GCR_IMAGES = [
    "calico/cni",
    "calico/node",
    "calico/typha",
]

ALL_IMAGES = []

# All images (non-FIPS tags)
for image in EXPECTED_IMAGES + IMAGES_NO_FIPS:
    version_suffixed = f"{variables.RELEASE_VERSION}"
    ALL_IMAGES.append((image, version_suffixed))
    for tag_suffix in TAG_SUFFIXES:
        tag_suffixed = f"{variables.RELEASE_VERSION}-{tag_suffix}"
        ALL_IMAGES.append((image, tag_suffixed))

# FIPS-enabled images (FIPS tags)
for image in EXPECTED_IMAGES:
    for tag_suffix in FIPS_TAG_SUFFIXES:
        tag_suffixed = f"{variables.RELEASE_VERSION}-{tag_suffix}"
        ALL_IMAGES.append((image, tag_suffixed))

# Windows images (no per-release tags)
for image in EXPECTED_WINDOWS_IMAGES:
    tag_suffixed = f"{variables.RELEASE_VERSION}"
    ALL_IMAGES.append((image, tag_suffixed))

ALL_IMAGES.sort()

print("Found {} separate image tags to test".format(len(ALL_IMAGES)))

def request_quay_image(image_name, image_version):
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer {}".format(variables.QUAY_TOKEN),
    }
    params = {"specificTag": image_version}
    api_url = f"https://quay.io/api/v1/repository/{image_name}/tag"
    resp = requests.get(api_url, headers=headers, params=params)
    return resp

@pytest.fixture(name="docker_client")
def create_docker_instance():
    """
    Create and return a Docker API client
    """
    return docker.from_env()

@pytest.mark.parametrize("image_name,image_version", ALL_IMAGES)
def test_quay_arch_tags_present(image_name, image_version):
    """
    Verify arch-specific images
    """
    print(f"[INFO] checking quay.io/{image_name}:{image_version}")
    resp = request_quay_image(image_name, image_version)
    if resp.status_code != 200:
        pytest.fail(
            f"Got status code {resp.status_code} from API URL {resp.request.url}"
        )
    if not resp.json()['tags']:
        print(resp.json())
        pytest.fail("API call returned no valid tags")


@pytest.mark.parametrize("image_name", EXPECTED_IMAGES)
def test_quay_release_tags_present(image_name):
    """
    Verify manifest images
    """
    print(f"[INFO] checking quay.io/{image_name}:{variables.RELEASE_VERSION}")
    resp = request_quay_image(image_name, variables.RELEASE_VERSION)
    if resp.status_code != 200:
        raise AssertionError(
            f"Got status code {resp.status_code} from API URL {resp.request.url}"
        )


@pytest.mark.parametrize("image_name", GCR_IMAGES)
def test_gcr_release_tag_present(docker_client, image_name):
    """
    Verify GCR images
    """
    gcr_name = image_name.replace("calico/", "")
    print(
        f"[INFO] checking gcr.io/projectcalico-org/{gcr_name}:{variables.RELEASE_VERSION}"
    )
    gcr_image_name = f'gcr.io/projectcalico-org/{gcr_name}:{variables.RELEASE_VERSION}'
    cmd = f'docker manifest inspect gcr.io/projectcalico-org/{gcr_name}:{variables.RELEASE_VERSION} | jq -r "."'

    docker_image = docker_client.images.get_registry_data(gcr_image_name)

    failed_arches = []
    for arch in DOCKER_ARCHS:
        if not docker_image.has_platform(arch):
            failed_arches.append(arch)

    if failed_arches:
        print(docker_image.attrs['Platforms'])
        print(f"Image is missing the following expected platforms: {', '.join(failed_arches)}")
        pytest.fail(f"Image is missing the following expected platforms: {', '.join(failed_arches)}")


@pytest.mark.parametrize("image_name", CHECK_IMAGES)
def test_docker_release_tag_present(docker_client, image_name):
    """
    Verify docker image manifest is correct
    """

    docker_image = docker_client.images.get_registry_data(image_name)

    failed_arches = []
    for arch in DOCKER_ARCHS:
        if not docker_image.has_platform(arch):
            failed_arches.append(arch)

    if failed_arches:
        print(docker_image.attrs['Platforms'])
        print(f"Image is missing the following expected platforms: {', '.join(failed_arches)}")
        pytest.fail(f"Image is missing the following expected platforms: {', '.join(failed_arches)}")

    return

@pytest.mark.parametrize("image_name", EXPECTED_WINDOWS_IMAGES)
def test_docker_release_windows_tag_present(docker_client, image_name):
    """
    Verify docker image manifest is correct
    """

    image_name_with_tag = f"{image_name}:{variables.RELEASE_VERSION}"

    docker_image = docker_client.images.get_registry_data(image_name_with_tag)

    if platform_count := len(docker_image.attrs['Platforms']) != 2:
        pytest.fail(f"Windows image {image_name} has {platform_count} platforms (expected 2)")


def test_operator_image_present():
    """
    Validate operator image exists
    """
    print(f"[INFO] checking {OPERATOR_IMAGE}")
    resp = request_quay_image("tigera/operator", variables.OPERATOR_VERSION)
    if resp.status_code != 200:
        raise AssertionError(
            f"Got status code {resp.status_code} from API URL {resp.request.url}"
        )
    assert resp.status_code == 200


def test_operator_images():
    """
    Validate operator images match expected versions
    """

    print(f"[INFO] getting image list from {OPERATOR_IMAGE}")

    cmd = f"docker pull {OPERATOR_IMAGE}"
    req = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    output = req.stdout.read()

    cmd = f"docker run --rm -t {OPERATOR_IMAGE} -print-images list"
    req = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    output = req.stdout.read()
    image_list = output.decode().splitlines()
    print(f"[INFO] got image list:")
    for line in image_list:
        print(f"[INFO]  {line}")

    for image_name in EXPECTED_IMAGES:
        if image_name not in OPERATOR_EXCLUDED_IMAGES:
            this_image = f"docker.io/{image_name}:{variables.RELEASE_VERSION}"
            print(f"[INFO] checking {this_image} is in the operator image list")
            if this_image not in image_list:
                raise AssertionError(f"{this_image} not found in operator image list")
