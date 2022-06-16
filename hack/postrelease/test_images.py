import json
import os
import requests
import subprocess
import yaml
from versions import RELEASE_VERSION, OPERATOR_VERSION

OPERATOR_IMAGE = "quay.io/tigera/operator:%s" % OPERATOR_VERSION

# Architectures we expect to be present in multi-arch image manifests.
EXPECTED_ARCHS = ["amd64", "arm64", "arm", "ppc64le"]

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


def test_quay_release_tag_present():
    for image_name in EXPECTED_IMAGES:
        if image_name not in EXCLUDED_IMAGES:
            print("[INFO] checking quay.io/%s:%s" % (image_name, RELEASE_VERSION))
            headers = {"content-type": "application/json"}
            req = requests.get(
                "https://quay.io/api/v1/repository/%s/tag/%s/images"
                % (image_name, RELEASE_VERSION),
                headers=headers,
            )
            assert req.status_code == 200


def test_gcr_release_tag_present():
    for image_name in GCR_IMAGES:
        gcr_name = image_name.replace("calico/", "")
        print(
            "[INFO] checking gcr.io/projectcalico-org/%s:%s"
            % (gcr_name, RELEASE_VERSION)
        )
        cmd = (
            'docker manifest inspect gcr.io/projectcalico-org/%s:%s | jq -r "."'
            % (gcr_name, RELEASE_VERSION)
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


def test_docker_release_tag_present():
    for image_name in EXPECTED_IMAGES:
        if image_name not in EXCLUDED_IMAGES:
            print("[INFO] checking %s:%s" % (image_name, RELEASE_VERSION))
            cmd = 'docker manifest inspect %s:%s | jq -r "."' % (
                image_name,
                RELEASE_VERSION,
            )
    
            req = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
            metadata = json.loads(req.stdout.read())
            found_archs = []
            print("[INFO] metadata: %s" % metadata)
            for platform in metadata["manifests"]:
                found_archs.append(platform["platform"]["architecture"])
    
            assert EXPECTED_ARCHS.sort() == found_archs.sort()
    
    for image in VPP_IMAGES:
        print("[INFO] checking %s:%s" % (image_name, RELEASE_VERSION))
        image_name = "%s:%s-calico%s" % (image, VPP_RELEASE, RELEASE_VERSION,)
        cmd = 'docker manifest inspect %s | jq -r "."' % image_name
        req = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        assert not req.stdout.read().startswith("no such manifest"), (
            "Got 'no such manifest' looking for VPP image %s" % image_name
        )

def test_operator_images():
    """
    This test verifies that the images reported by the given operator 
    match the expected Calico version.
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
            this_image = "docker.io/%s:%s" % (image_name, RELEASE_VERSION)
            print(
                "[INFO] checking %s is in the operator image list" % this_image
            )
            assert this_image in image_list, (
                "%s not found in operator image list" % this_image
            )


# VPP specific tests.
VPP_IMAGES = ["calicovpp/agent", "calicovpp/vpp", "calicovpp/init-eks"]
VPP_RELEASE = os.getenv("VPP_BRANCH")
VPP_EXPECTED_ARCHS = ["amd64"]

def test_vpp_branch():
    assert VPP_RELEASE != "master", "vppbranch cannot be 'master' for a release"


def test_operator_image_present():
    print("[INFO] checking %s" % OPERATOR_IMAGE)
    headers = {"content-type": "application/json"}
    req = requests.get(
        "https://quay.io/api/v1/repository/tigera/operator/tag/%s/images"
        % (OPERATOR_VERSION),
        headers=headers,
    )
    assert req.status_code == 200, "Bad response: %s" % req.status_code
