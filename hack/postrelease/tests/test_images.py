import json
import subprocess

import requests

import pytest

import variables

OPERATOR_IMAGE = f"quay.io/tigera/operator:{variables.OPERATOR_VERSION}"

# Architectures we expect to be present in multi-arch image manifests.
EXPECTED_ARCHS = ["amd64", "arm64", "armv7", "ppc64le", "s390x"]

# Images we expect to exist as part of a Calico release, without 
# a registry assigned.
EXPECTED_IMAGES = [
  "calico/node",
  "calico/ctl", 
  "calico/apiserver",
  "calico/typha",
  "calico/cni",
  "calico/kube-controllers",
  "calico/upgrade",
  "calico/windows",
  "calico/flannel-migration-controller",
  "calico/dikastes",
  "calico/pilot-webhook",
  "calico/pod2daemon-flexvol",
  "calico/csi",
]

TAG_SUFFIXES = [
    "amd64",
    "arm64",
    "armv7",
    "fips-amd64",
    "fips",
    "ppc64le",
    "s390x",
]

# Images that we exclude from the assertions below.
EXCLUDED_IMAGES = ["calico/pilot-webhook", "calico/upgrade"]
OPERATOR_EXCLUDED_IMAGES = EXCLUDED_IMAGES + [
    "calico/dikastes",
    "calico/flannel-migration-controller",
    "calico/ctl",
    "calico/windows",
    "calico/csi",
]

CHECK_IMAGES = [img for img in EXPECTED_IMAGES if img not in EXCLUDED_IMAGES]

# Images that we expect to be published to GCR.
GCR_IMAGES = [
    "calico/node", 
    "calico/cni", 
    "calico/typha",
]

ALL_IMAGES = []
for image in EXPECTED_IMAGES:
    for tag_suffix in TAG_SUFFIXES:
        tag_suffixed = f"{variables.RELEASE_VERSION}-{tag_suffix}"
        ALL_IMAGES.append((image, tag_suffixed))

print(("Found {} separate image tags to test".format(len(ALL_IMAGES))))

def request_quay_image(image_name, image_version):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(variables.QUAY_API_TOKEN)
        }
    params = {'specificTag': image_version}
    api_url = f"https://quay.io/api/v1/repository/{image_name}/tag"
    resp = requests.get(api_url, headers=headers, params=params)
    return resp

@pytest.mark.parametrize("image_name,image_version", ALL_IMAGES)
def test_quay_arch_tags_present(image_name, image_version):
    """
    Verify arch-specific images
    """
    print(f"[INFO] checking quay.io/{image_name}:{image_version}")
    resp = request_quay_image(image_name, image_version)
    if resp.status_code != 200:
        raise AssertionError(f"Got status code {resp.status_code} from API URL {resp.request.url}")

@pytest.mark.parametrize("image_name", EXPECTED_IMAGES)
def test_quay_release_tags_present(image_name):
    """
    Verify manifest images
    """
    print(f"[INFO] checking quay.io/{image_name}:{variables.RELEASE_VERSION}")
    resp = request_quay_image(image_name, variables.RELEASE_VERSION)
    if resp.status_code != 200:
        raise AssertionError(f"Got status code {resp.status_code} from API URL {resp.request.url}")

@pytest.mark.parametrize("image_name", GCR_IMAGES)
def test_gcr_release_tag_present(image_name):
    """
    Verify GCR images
    """
    gcr_name = image_name.replace("calico/", "")
    print(f"[INFO] checking gcr.io/projectcalico-org/{gcr_name}:{variables.RELEASE_VERSION}")
    cmd = f'docker manifest inspect gcr.io/projectcalico-org/{gcr_name}:{variables.RELEASE_VERSION} | jq -r "."'
    
    req = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    try:
        metadata = json.loads(req.stdout.read())
    except ValueError:
        print("[ERROR] Didn't get json back from docker manifest inspect.  Does image exist?")
        assert False
    found_archs = []
    for platform in metadata["manifests"]:
        found_archs.append(platform["platform"]["architecture"])
    
    assert EXPECTED_ARCHS.sort() == found_archs.sort()


@pytest.mark.parametrize("image_name", CHECK_IMAGES)
def test_docker_release_tag_present(image_name):
    """
    Verify docker image manifest is correct
    """
    cmd = f'docker manifest inspect {image_name}:{variables.RELEASE_VERSION} | jq -r "."'

    prog = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    returncode = prog.wait()

    docker_output = prog.stdout.read()
    docker_error = prog.stderr.read()

    if not docker_output:
        if "toomanyrequests" in docker_error:
            raise RuntimeError("Rate limited by docker hub")
        elif "authentication required" in docker_error:
            raise RuntimeError(f"Docker request requires authentication (image {image_name})")
        else:
            raise AssertionError(f"Docker command failed: {docker_error}")
    metadata = json.loads(docker_output)
    found_archs = []
    print(f"[INFO] metadata: {metadata}")
    for platform in metadata["manifests"]:
        found_archs.append(platform["platform"]["architecture"])

    assert EXPECTED_ARCHS.sort() == found_archs.sort()

def test_operator_image_present():
    """
    Validate operator image exists
    """
    print(f"[INFO] checking {OPERATOR_IMAGE}")
    resp = request_quay_image("tigera/operator", variables.OPERATOR_VERSION)
    if resp.status_code != 200:
        raise AssertionError(f"Got status code {resp.status_code} from API URL {resp.request.url}")
    assert resp.status_code == 200

def test_operator_images():
    """
    Validate operator images match expected versions
    """

    print(f"[INFO] getting image list from {OPERATOR_IMAGE}")

    cmd = f"docker pull {OPERATOR_IMAGE}"
    req = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = req.stdout.read()


    cmd = f"docker run --rm -t {OPERATOR_IMAGE} -print-images list"
    req = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
