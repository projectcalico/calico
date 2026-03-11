#!/bin/bash

# This script updates the manifests in this directory using helm.
# Values files for the manifests in this directory can be found in
# ../calico/charts/values.

# Helm binary to use. Default to the one installed by the Makefile.
HELM=${HELM:-../bin/helm}

# yq binary to use. Default to the one installed by the Makefile.
YQ=${YQ:-../bin/yq}

if [[ ! -f $HELM ]]; then
  echo "[ERROR] Helm binary ${HELM} not found."
  exit 1
fi
if [[ ! -f $YQ ]]; then
  echo "[ERROR] yq binary ${YQ} not found."
  exit 1
fi

# Get versions to install.
defaultCalicoVersion=$($YQ .version <../charts/calico/values.yaml)
CALICO_VERSION=${PRODUCT_VERSION:-$defaultCalicoVersion}

defaultRegistry=$($YQ .node.registry <../charts/calico/values.yaml)
REGISTRY=${REGISTRY:-$defaultRegistry}

defaultOperatorVersion=$($YQ .tigeraOperator.version <../charts/tigera-operator/values.yaml)
OPERATOR_VERSION=${OPERATOR_VERSION:-$defaultOperatorVersion}

defaultOperatorRegistry=$($YQ .tigeraOperator.registry <../charts/tigera-operator/values.yaml)
OPERATOR_REGISTRY=${OPERATOR_REGISTRY_OVERRIDE:-$defaultOperatorRegistry}

defaultOperatorImage=$($YQ .tigeraOperator.image <../charts/tigera-operator/values.yaml)
OPERATOR_IMAGE=${OPERATOR_IMAGE_OVERRIDE:-$defaultOperatorImage}

NON_HELM_MANIFEST_IMAGES="apiserver windows ctl csi node-driver-registrar dikastes flannel-migration-controller"

echo "Generating manifests for Calico=$CALICO_VERSION and tigera-operator=$OPERATOR_VERSION"

##########################################################################
# Build the operator manifest.
##########################################################################
cat <<EOF > tigera-operator.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: tigera-operator
  labels:
    name: tigera-operator
    pod-security.kubernetes.io/enforce: privileged
EOF

${HELM} -n tigera-operator template \
	--no-hooks \
	--set installation.enabled=false \
	--set apiServer.enabled=false \
	--set whisker.enabled=false \
	--set goldmane.enabled=false \
	--set tigeraOperator.version=$OPERATOR_VERSION \
	--set tigeraOperator.image=$OPERATOR_IMAGE \
	--set tigeraOperator.registry=$OPERATOR_REGISTRY \
	--set calicoctl.tag=$CALICO_VERSION \
	--set calicoctl.image=$REGISTRY/ctl \
	../charts/tigera-operator >> tigera-operator.yaml

##########################################################################
# Build CRD manifest.
#
# This manifest is used in "Calico the hard way" documentation.
##########################################################################
echo "# CustomResourceDefinitions for Calico the Hard Way" > crds.yaml
for FILE in $(ls ../charts/calico/crds); do
	${HELM} template ../charts/calico \
		--include-crds \
		--show-only $FILE \
		--set version=$CALICO_VERSION \
		--set node.registry=$REGISTRY \
		--set calicoctl.registry=$REGISTRY \
		--set typha.registry=$REGISTRY \
		--set cni.registry=$REGISTRY \
		--set kubeControllers.registry=$REGISTRY \
		--set flannelMigration.registry=$REGISTRY \
		--set dikastes.registry=$REGISTRY \
		--set csi-driver.registry=$REGISTRY \
		-f ../charts/values/calico.yaml >> crds.yaml
done

##########################################################################
# Build manifest which includes both Calico and Operator CRDs.
##########################################################################
echo "# crd.projectcalico.org/v1 and operator.tigera.io/v1 APIs" > v1_crd_projectcalico_org.yaml
for FILE in $(ls ../charts/crd.projectcalico.org.v1/templates/*.yaml | xargs -n1 basename); do
	${HELM} template \
		--show-only templates/$FILE \
		--set version=$CALICO_VERSION \
		../charts/crd.projectcalico.org.v1 >> v1_crd_projectcalico_org.yaml
done
for FILE in $(ls ../charts/crd.projectcalico.org.v1/templates/calico/*.yaml | xargs -n1 basename); do
	${HELM} template \
		--show-only templates/calico/$FILE \
		--set version=$CALICO_VERSION \
		../charts/crd.projectcalico.org.v1 >> v1_crd_projectcalico_org.yaml
done

# Maintain legacy operator-crds.yaml for a while.
cp v1_crd_projectcalico_org.yaml operator-crds.yaml

echo "# projectcalico.org/v3 and operator.tigera.io/v1 APIs" > v3_projectcalico_org.yaml
for FILE in $(ls ../charts/projectcalico.org.v3/templates/*.yaml | xargs -n1 basename); do
	${HELM} template \
		--show-only templates/$FILE \
		--set version=$CALICO_VERSION \
		../charts/projectcalico.org.v3 >> v3_projectcalico_org.yaml
done
for FILE in $(ls ../charts/projectcalico.org.v3/templates/calico/*.yaml | xargs -n1 basename); do
	${HELM} template \
		--show-only templates/calico/$FILE \
		--set version=$CALICO_VERSION \
		../charts/projectcalico.org.v3 >> v3_projectcalico_org.yaml
done

##########################################################################
# Build Calico manifests.
#
# To add a new manifest to this directory, define
# a new values file in ../charts/values/
##########################################################################
VALUES_FILES=$(cd ../charts/values && find . -type f -name "*.yaml")

for FILE in $VALUES_FILES; do
	echo "Generating manifest from charts/values/$FILE"
	${HELM} -n kube-system template \
		../charts/calico \
		--set version=$CALICO_VERSION \
		-f ../charts/values/$FILE > $FILE
done

##########################################################################
# Build tigera-operator manifests for OCP.
#
# OCP requires resources in their own yaml files, so output to a dir.
# Then do a bit of cleanup to reduce the directory depth to 1.
##########################################################################
${HELM} template \
	-n tigera-operator \
	../charts/tigera-operator/ \
	--output-dir ocp \
	--no-hooks \
	--set installation.kubernetesProvider=OpenShift \
	--set installation.enabled=false \
	--set apiServer.enabled=false \
	--set goldmane.enabled=false \
	--set whisker.enabled=false \
	--set tigeraOperator.image=$OPERATOR_IMAGE \
	--set tigeraOperator.version=$OPERATOR_VERSION \
	--set tigeraOperator.registry=$OPERATOR_REGISTRY \
	--set calicoctl.image=$REGISTRY/ctl \
	--set calicoctl.tag=$CALICO_VERSION
# The first two lines are a newline and a yaml separator - remove them.
find ocp/tigera-operator -name "*.yaml" -print0 | xargs -0 sed -i -e 1,2d
mv $(find ocp/tigera-operator -name "*.yaml") ocp/ && rm -r ocp/tigera-operator

# Generating the upgrade manifest for OCP.
# It excludes files specific to configuring the BPF dataplane, CRs (03-cr-*) and CRDs to maintain compatibility and not change the existing configuration in already installed clusters.
OCP_VALUES_FILES=$(ls ocp | grep -v -e '01-configmap-kubernetes-services-endpoint\.yaml' -e '02-configmap-calico-resources\.yaml' -e '^03-cr-' -e 'cluster-network-operator\.yaml' -e '\.*crd\.*' -e 'mutatingadmissionpolicy')
rm -f tigera-operator-ocp-upgrade.yaml
for FILE in $OCP_VALUES_FILES; do
  cat "ocp/$FILE" >> tigera-operator-ocp-upgrade.yaml
  echo -e "---" >> tigera-operator-ocp-upgrade.yaml  # Add separator
done

##########################################################################
# Replace image registry and/or versions for "static" Calico manifests.
##########################################################################
echo "Replacing image versions for static manifests"
for img in $NON_HELM_MANIFEST_IMAGES; do
  curr_img=${defaultRegistry}/${img}
  new_img=${REGISTRY}/${img}
  echo "$curr_img:$defaultCalicoVersion --> $new_img:$CALICO_VERSION"
  find . -type f -exec sed -i "s|${curr_img}:[A-Za-z0-9_.-]*|${new_img}:$CALICO_VERSION|g" {} \;
done
