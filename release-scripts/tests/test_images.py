import json
import os
import requests
import subprocess
import yaml

DOCS_PATH = '/docs' if os.environ.get('CALICO_DOCS_PATH') is None else os.environ.get('CALICO_DOCS_PATH')
RELEASE_STREAM = os.environ.get('RELEASE_STREAM')
EXCLUDED_IMAGES = ['calico/pilot-webhook',
                   'calico/upgrade',
                   'quay.io/coreos/flannel']

GCR_IMAGES = ['calico/node',
              'calico/cni',
              'calico/typha']
EXPECTED_ARCHS = ['amd64', 'arm64', 'ppc64le']

VERSIONS_WITHOUT_FLANNEL_MIGRATION = ['v3.8', 'v3.7', 'v3.6', 'v3.5', 'v3.4', 'v3.3', 'v3.2', 'v3.1', 'v3.0']
if RELEASE_STREAM in VERSIONS_WITHOUT_FLANNEL_MIGRATION:
    EXCLUDED_IMAGES.append('calico/flannel-migration-controller')
    print('[INFO] excluding "calico/flannel-migration-controller" for older release')

with open('%s/_data/versions.yml' % DOCS_PATH) as f:
    versions = yaml.safe_load(f)
    RELEASE_VERSION = versions[0]['title']
    print('[INFO] using _data/versions.yaml, discovered version: %s' % RELEASE_VERSION)

def test_operator_image_present():
    with open('%s/_data/versions.yml' % DOCS_PATH) as versionsFile:
        versions = yaml.safe_load(versionsFile)
        for version in versions:
            if version["title"] == RELEASE_VERSION:
                # Found matching version. Perform the test.
                operator = version["tigera-operator"]
                img = "%s/%s:%s" % (operator["registry"], operator["image"], operator["version"])
                print('[INFO] checking %s' % img)
                headers = {'content-type': 'application/json'}
                req = requests.get("https://quay.io/api/v1/repository/tigera/operator/tag/%s/images" % (
                    operator["version"]), headers=headers)
                assert req.status_code == 200
                return
        assert False, "Unable to find matching version"

def test_quay_release_tag_present():
    with open('%s/_config.yml' % DOCS_PATH) as config:
        images = yaml.safe_load(config)
        for image in images['imageNames']:
            if images['imageNames'][image] not in EXCLUDED_IMAGES:
                print('[INFO] checking quay.io/%s:%s' % (images['imageNames'][image], RELEASE_VERSION))

                headers = {'content-type': 'application/json'}
                req = requests.get("https://quay.io/api/v1/repository/%s/tag/%s/images" % (
                    images['imageNames'][image], RELEASE_VERSION), headers=headers)
                assert req.status_code == 200


def test_gcr_release_tag_present():
    with open('%s/_config.yml' % DOCS_PATH) as config:
        images = yaml.safe_load(config)
        for image in images['imageNames']:
            if images['imageNames'][image] in GCR_IMAGES:
                gcr_name = images['imageNames'][image].replace('calico/', '')
                print('[INFO] checking gcr.io/projectcalico-org/%s:%s' % (gcr_name, RELEASE_VERSION))
                cmd = 'docker manifest inspect gcr.io/projectcalico-org/%s:%s | jq -r "."' % (gcr_name, RELEASE_VERSION)

                req = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
                try:
                    metadata = json.loads(req.stdout.read())
                except ValueError:
                    print("[ERROR] Didn't get json back from docker manifest inspect.  Does image exist?")
                    assert False
                found_archs = []
                for platform in metadata['manifests']:
                    found_archs.append(platform['platform']['architecture'])

                assert EXPECTED_ARCHS == found_archs


def test_docker_release_tag_present():
    with open('%s/_config.yml' % DOCS_PATH) as config:
        images = yaml.safe_load(config)
        for image in images['imageNames']:
            if images['imageNames'][image] not in EXCLUDED_IMAGES:
                print('[INFO] checking %s:%s' % (images['imageNames'][image], RELEASE_VERSION))
                cmd = 'docker manifest inspect %s:%s | jq -r "."' % (images['imageNames'][image], RELEASE_VERSION)

                req = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
                metadata = json.loads(req.stdout.read())
                found_archs = []
                for platform in metadata['manifests']:
                    found_archs.append(platform['platform']['architecture'])

                assert EXPECTED_ARCHS.sort() == found_archs.sort()
