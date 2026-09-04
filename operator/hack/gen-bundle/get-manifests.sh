#!/bin/bash
#
# This script stages the Calico and operator manifests that
# `operator-sdk generate bundle` reads to build a ClusterServiceVersion.
#
# This script should not be run directly. See the bundle target in the Makefile.
set -eu

if [[ -z "${BUNDLE_CRD_DIR}" ]]; then
    echo "BUNDLE_CRD_DIR is not set"
    exit 1
fi
if [[ -z "${BUNDLE_DEPLOY_DIR}" ]]; then
    echo "BUNDLE_DEPLOY_DIR is not set"
    exit 1
fi

# Start from empty staging directories. Leftovers from an earlier run would
# otherwise be picked up by operator-sdk and end up in the bundle - for example
# a CRD that has since been dropped from CALICO_RESOURCES below.
rm -rf "${BUNDLE_CRD_DIR}" "${BUNDLE_DEPLOY_DIR}"
mkdir -p "${BUNDLE_CRD_DIR}" "${BUNDLE_DEPLOY_DIR}"

echo "Building bundle from ${BUNDLE_DEPLOY_DIR}"

# Get the base path for the Calico docs site. This will be used to download manifests.
CALICO_BASE_URL=https://raw.githubusercontent.com/projectcalico/calico

if [ -f config/calico_versions.yml ]; then
    CALICO_VERSION=$(yq '.components.typha.version' < config/calico_versions.yml)
else
    echo "Could not find Calico versions file."
    exit 1
fi

CALICO_BASE_URL=${CALICO_BASE_URL}/${CALICO_VERSION}

# Download operator manifests. For CSV generation we use a version of the
# operator deployment manifest that doesn't include an init container and
# volumes for creating install-time resources.
function downloadOperatorManifests() {
    curl -fsSL ${CALICO_BASE_URL}/manifests/ocp-tigera-operator-no-resource-loading.yaml --output ${BUNDLE_DEPLOY_DIR}/operator.yaml
    curl -fsSL ${CALICO_BASE_URL}/manifests/ocp/02-role-tigera-operator.yaml --output ${BUNDLE_DEPLOY_DIR}/role.yaml
    # The binding is required unlike in earlier bundle generation. The
    # 'operator-sdk generate bundle' command combines clusterroles bound to service
    # accounts. The resulting permissions is set to the CSV's
    # spec.install.clusterPermissions field.
    curl -fsSL ${CALICO_BASE_URL}/manifests/ocp/02-rolebinding-tigera-operator.yaml --output ${BUNDLE_DEPLOY_DIR}/rolebinding-tigera-operator.yaml
}

# Stage the sample CRs that become the CSV's alm-examples annotation, which is
# what OperatorHub offers users as a starting point in its "Create instance"
# forms. Only kinds whose CRD the bundle ships belong here - an example for a
# kind the CSV does not own is dropped, and every owned CRD without an example
# is reported by 'operator-sdk bundle validate'.
function copySampleCRs() {
    cp config/samples/operator_v1_installation.yaml ${BUNDLE_DEPLOY_DIR}/
    cp config/samples/operator_v1_imageset.yaml ${BUNDLE_DEPLOY_DIR}/
}

# Copy over and update the v1beta1 operator crds required for Calico.
function generateOperatorCRDs() {
    # Copy the crds we need to the bundle.
    cp pkg/crds/operator/operator.tigera.io_installations.yaml ${BUNDLE_CRD_DIR}/
    cp pkg/crds/operator/operator.tigera.io_tigerastatuses.yaml ${BUNDLE_CRD_DIR}/
    cp pkg/crds/operator/operator.tigera.io_imagesets.yaml ${BUNDLE_CRD_DIR}/

    # Clean up the crds.
    for f in `find ${BUNDLE_CRD_DIR}/ -name 'operator.tigera.io*'`; do
        # Remove empty lines and the three dashes that separate directives.
        sed -i '/^$/d' ${f}
        sed -i '/^---$/d' ${f}
    done
}

# The Calico CRDs the bundle ships. Keep this list, the owned CRDs in
# config/manifests/bases/tigera-operator.clusterserviceversion.yaml, and the
# internal-objects annotation in that same file in sync: a CRD listed here but
# not described there generates a bundle-validation warning, and a CRD described
# there but not listed here is advertised by the CSV without being installed.
CALICO_RESOURCES="
bgpconfigurations
bgppeers
blockaffinities
caliconodestatuses
clusterinformations
felixconfigurations
globalnetworkpolicies
globalnetworksets
hostendpoints
ipamblocks
ipamconfigs
ipamhandles
ippools
ipreservations
kubecontrollersconfigurations
networkpolicies
networksets
"

function downloadCalicoCRDs() {
    # Download the Calico CRDs into CRD dir.
    for resource in $CALICO_RESOURCES; do
        echo "  [curl] Downloading libcalico-go CRD ${resource}"
        curl -fsSL ${CALICO_BASE_URL}/libcalico-go/config/crd/crd.projectcalico.org_${resource}.yaml --output ${BUNDLE_CRD_DIR}/crd.projectcalico.org_${resource}.yaml
    done
}

downloadOperatorManifests
copySampleCRs
generateOperatorCRDs
downloadCalicoCRDs
