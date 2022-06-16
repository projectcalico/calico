import json
import os
import requests
import subprocess
import yaml

DOCS_PATH = (
    "/docs"
    if os.environ.get("CALICO_DOCS_PATH") is None
    else os.environ.get("CALICO_DOCS_PATH")
)
RELEASE_STREAM = os.environ.get("RELEASE_STREAM")
EXCLUDED_IMAGES = ["calico/pilot-webhook", "calico/upgrade", "quay.io/coreos/flannel"]
OPERATOR_EXCLUDED_IMAGES = EXCLUDED_IMAGES + [
    "calico/dikastes",
    "calico/flannel-migration-controller",
    "calico/ctl",
    "calico/windows",
    "calico/csi",
]

GCR_IMAGES = ["calico/node", "calico/cni", "calico/typha"]
EXPECTED_ARCHS = ["amd64", "arm64", "arm", "ppc64le"]

VERSIONS_WITHOUT_IMAGE_LIST = [
    "v1.13",
    "v1.12",
    "v1.11",
    "v1.10",
    "v1.9",
    "v1.8",
    "v1.7",
    "v1.6",
    "v1.5",
    "v1.4",
    "v1.3",
    "v1.2",
    "v1.1",
    "v1.0",
]

VPP_IMAGES = ["calicovpp/agent", "calicovpp/vpp", "calicovpp/init-eks"]
with open("%s/_config.yml" % DOCS_PATH) as configFile:
    config = yaml.safe_load(configFile)
    VPP_RELEASE = config["defaults"][0]["values"]["vppbranch"]

def test_vpp_branch():
    assert VPP_RELEASE != "master", "vppbranch cannot be 'master' for a release"

VPP_EXPECTED_ARCHS = ["amd64"]

VERSIONS_WITHOUT_FLANNEL_MIGRATION = [
    "v3.8",
    "v3.7",
    "v3.6",
    "v3.5",
    "v3.4",
    "v3.3",
    "v3.2",
    "v3.1",
    "v3.0",
]
if RELEASE_STREAM in VERSIONS_WITHOUT_FLANNEL_MIGRATION:
    EXCLUDED_IMAGES.append("calico/flannel-migration-controller")
    print('[INFO] excluding "calico/flannel-migration-controller" for older release')

with open("%s/_data/versions.yml" % DOCS_PATH) as f:
    versions = yaml.safe_load(f)
    RELEASE_VERSION = versions[0]["title"]
    print("[INFO] using _data/versions.yaml, discovered version: %s" % RELEASE_VERSION)


def test_operator_image_present():
    with open("%s/_data/versions.yml" % DOCS_PATH) as versionsFile:
        versions = yaml.safe_load(versionsFile)
        for version in versions:
            if version["title"] == RELEASE_VERSION:
                # Found matching version. Perform the test.
                operator = version["tigera-operator"]
                img = "%s/%s:%s" % (
                    operator["registry"],
                    operator["image"],
                    operator["version"],
                )
                print("[INFO] checking %s" % img)
                headers = {"content-type": "application/json"}
                req = requests.get(
                    "https://quay.io/api/v1/repository/tigera/operator/tag/%s/images"
                    % (operator["version"]),
                    headers=headers,
                )
                assert req.status_code == 200
                return
        assert False, "Unable to find matching version"


def test_quay_release_tag_present():
    with open("%s/_config.yml" % DOCS_PATH) as config:
        images = yaml.safe_load(config)
        for image in images["imageNames"]:
            image_name = images["imageNames"][image].replace("docker.io/", "")
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
    with open("%s/_config.yml" % DOCS_PATH) as config:
        images = yaml.safe_load(config)
        for image in images["imageNames"]:
            image_name = images["imageNames"][image].replace("docker.io/", "")
            if image_name in GCR_IMAGES:
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
    with open("%s/_config.yml" % DOCS_PATH) as config:
        images = yaml.safe_load(config)
        for image in images["imageNames"]:
            image_name = images["imageNames"][image].replace("docker.io/", "")
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
    with open("%s/_data/versions.yml" % DOCS_PATH) as versionsFile:
        versions = yaml.safe_load(versionsFile)
        for version in versions:
            if version["title"] == RELEASE_VERSION:
                # Found matching version. Perform the test.
                operator = version["tigera-operator"]
                img = "%s/%s:%s" % (
                    operator["registry"],
                    operator["image"],
                    operator["version"],
                )
                break
    if operator["version"] not in VERSIONS_WITHOUT_IMAGE_LIST:
        print("[INFO] getting image list from %s" % img)
        cmd = "docker pull %s" % img
        req = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        output = req.stdout.read()
        print("[INFO] Pulling operator image:\n%s" % output)

        cmd = "docker run --rm -t %s -print-images list" % img
        req = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        output = req.stdout.read()
        image_list = output.splitlines()
        print("[INFO] got image list:\n%s" % image_list)

        with open("%s/_config.yml" % DOCS_PATH) as config:
            images = yaml.safe_load(config)
            for image in images["imageNames"]:
                image_name = images["imageNames"][image]
                if image_name.replace("docker.io/", "") not in OPERATOR_EXCLUDED_IMAGES:
                    this_image = "%s:%s" % (image_name, RELEASE_VERSION)
                    print(
                        "[INFO] checking %s is in the operator image list" % this_image
                    )
                    assert this_image in image_list, (
                        "%s not found in operator image list" % this_image
                    )
    else:
        print("[INFO] This version of operator does not have an image list")
