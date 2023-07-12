import json
import subprocess

import requests
from parameterized import parameterized

import variables

OPERATOR_IMAGE = "quay.io/tigera/operator:%s" % variables.OPERATOR_VERSION

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


# Images that we expect to be published to GCR.
GCR_IMAGES = [
    "calico/node", 
    "calico/cni", 
    "calico/typha",
]

ALL_IMAGES = []
for image in EXPECTED_IMAGES:
    for tag_suffix in TAG_SUFFIXES:
        tag_suffixed = "{}-{}".format(variables.RELEASE_VERSION, tag_suffix)
        ALL_IMAGES.append((image, tag_suffixed))

print("Found {} separate image tags to test".format(len(ALL_IMAGES)))

def request_quay_image(image_name, image_version):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer {}'.format(variables.QUAY_API_TOKEN)
        }
    params = {'specificTag': image_version}
    api_url = "https://quay.io/api/v1/repository/%s/tag" % (image_name)
    resp = requests.get(api_url, headers=headers, params=params)
    return resp

@parameterized(ALL_IMAGES)
def test_quay_arch_tags_present(image_name, image_version):
    """
    Verify arch-specific images
    """
    print("[INFO] checking quay.io/%s:%s" % (image_name, image_version))
    resp = request_quay_image(image_name, image_version)
    if resp.status_code != 200:
        raise AssertionError("Got status code {} from API URL {}".format(resp.status_code, resp.request.url))
    assert resp.status_code == 200

@parameterized(EXPECTED_IMAGES)
def test_quay_release_tags_present(image_name):
    """
    Verify manifest images
    """
    print("[INFO] checking quay.io/%s:%s" % (image_name, variables.RELEASE_VERSION))
    resp = request_quay_image(image_name, variables.RELEASE_VERSION)
    if resp.status_code != 200:
        raise AssertionError("Got status code {} from API URL {}".format(resp.status_code, resp.request.url))
    assert resp.status_code == 200

@parameterized(GCR_IMAGES)
def test_gcr_release_tag_present(image_name):
    """
    Verify GCR images
    """
    gcr_name = image_name.replace("calico/", "")
    print(
        "[INFO] checking gcr.io/projectcalico-org/%s:%s"
        % (gcr_name, variables.RELEASE_VERSION)
    )
    cmd = (
        'docker manifest inspect gcr.io/projectcalico-org/%s:%s | jq -r "."'
        % (gcr_name, variables.RELEASE_VERSION)
    )
    
    req = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    try:
        metadata = json.loads(req.stdout.read())
    except ValueError:
        print(
            "[ERROR] Didn't get json back from docker manifest inspect.  Does image exist?"
        )
        assert False
    found_archs = []
    for platform in metadata["manifests"]:
        found_archs.append(platform["platform"]["architecture"])
    
    assert EXPECTED_ARCHS.sort() == found_archs.sort()


@parameterized(EXPECTED_IMAGES)
def test_docker_release_tag_present(image_name):
    """
    Verify docker image manifest is correct
    """
    cmd = 'docker manifest inspect %s:%s | jq -r "."' % (
        image_name,
        variables.RELEASE_VERSION,
    )

    prog = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    returncode = prog.wait()

    docker_output = prog.stdout.read()
    docker_error = prog.stderr.read()

    if not docker_output:
        if "toomanyrequests" in docker_error:
            raise RuntimeError("Rate limited by docker hub")
        elif "authentication required" in docker_error:
            raise RuntimeError("Docker request requires authentication")
        else:
            raise AssertionError("Docker command failed: {}".format(docker_error))
    metadata = json.loads(docker_output)
    found_archs = []
    print("[INFO] metadata: %s" % metadata)
    for platform in metadata["manifests"]:
        found_archs.append(platform["platform"]["architecture"])

    assert EXPECTED_ARCHS.sort() == found_archs.sort()

def test_operator_images():
    """
    Validate operator images match expected versions
    """

    print("[INFO] getting image list from %s" % OPERATOR_IMAGE)
    cmd = "docker pull %s" % OPERATOR_IMAGE
    req = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output = req.stdout.read()
    print("[INFO] Pulling operator image:\n%s" % output)

    cmd = "docker run --rm -t %s -print-images list" % OPERATOR_IMAGE
    req = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    output = req.stdout.read()
    image_list = output.splitlines()
    print("[INFO] got image list:\n%s" % image_list)

    for image_name in EXPECTED_IMAGES:
        if image_name not in OPERATOR_EXCLUDED_IMAGES:
            this_image = "docker.io/%s:%s" % (image_name, variables.RELEASE_VERSION)
            print(
                "[INFO] checking %s is in the operator image list" % this_image
            )
            assert this_image in image_list, (
                "%s not found in operator image list" % this_image
            )

def test_operator_image_present():
    """
    Validate operator image exists
    """
    print("[INFO] checking %s" % OPERATOR_IMAGE)
    resp = request_quay_image("tigera/operator", variables.OPERATOR_VERSION)
    if resp.status_code != 200:
        raise AssertionError("Got status code {} from API URL {}".format(resp.status_code, resp.request.url))
    assert resp.status_code == 200
