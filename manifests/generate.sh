#!/bin/bash

# This script updates the manifests in this directory using helm.
# Values files for the manifests in this directory can be found in
# ../calico/charts/values.

# Helm binary to use. Default to the one installed by the Makefile.
HELM=${HELM:-../bin/helm}
YQ=${YQ:-../bin/yq}

# Get versions to install.
defaultCalicoVersion=$($YQ .version <../charts/calico/values.yaml)
CALICO_VERSION=${CALICO_VERSION:-$defaultCalicoVersion}

defaultRegistry=$($YQ .node.registry <../charts/calico/values.yaml)
REGISTRY=${REGISTRY:-$defaultRegistry}

defaultOperatorVersion=$($YQ .tigeraOperator.version <../charts/tigera-operator/values.yaml)
OPERATOR_VERSION=${OPERATOR_VERSION:-$defaultOperatorVersion}

defaultOperatorRegistry=$($YQ .tigeraOperator.registry <../charts/tigera-operator/values.yaml)
OPERATOR_REGISTRY=${OPERATOR_REGISTRY:-$defaultOperatorRegistry}

defaultOperatorImage=$($YQ .tigeraOperator.image <../charts/tigera-operator/values.yaml)
OPERATOR_IMAGE=${OPERATOR_IMAGE:-$defaultOperatorImage}

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
	        --set flannel.registry=$REGISTRY \
	        --set flannelMigration.registry=$REGISTRY \
	        --set dikastes.registry=$REGISTRY \
	        --set csi-driver.registry=$REGISTRY \
		-f ../charts/values/calico.yaml >> crds.yaml
done

##########################################################################
# Build manifest which includes both Calico and Operator CRDs.
##########################################################################
echo "# CustomResourceDefinitions for Calico and Tigera operator" > operator-crds.yaml
for FILE in $(ls ../charts/tigera-operator/crds/*.yaml | xargs -n1 basename); do
	${HELM} -n tigera-operator template \
		--include-crds \
		--show-only $FILE \
	        --set version=$CALICO_VERSION \
	       ../charts/tigera-operator >> operator-crds.yaml
done
for FILE in $(ls ../charts/calico/crds); do
	${HELM} template ../charts/calico \
		--include-crds \
		--show-only $FILE \
	        --set version=$CALICO_VERSION \
		-f ../charts/values/calico.yaml >> operator-crds.yaml
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
find ocp/tigera-operator -name "*.yaml" | xargs sed -i -e 1,2d
mv $(find ocp/tigera-operator -name "*.yaml") ocp/ && rm -r ocp/tigera-operator

# Generating the upgrade manifest for OCP.
# It excludes the CRs (01-*) and the specific BPF files to maintain compatibility with iptables.
VALUES_FILES=$(ls ocp | grep -v -e '^01-' -e 'cluster-network-operator.yaml' -e '02-configmap-calico-resources.yaml')
rm -f tigera-operator-ocp-upgrade.yaml
for FILE in $VALUES_FILES; do
  cat "ocp/$FILE" >> tigera-operator-ocp-upgrade.yaml
  echo -e "---" >> tigera-operator-ocp-upgrade.yaml  # Add divisor
done
# Remove the last separator (last line)
sed -i -e '$ d' tigera-operator-ocp-upgrade.yaml

##########################################################################
# Replace image versions for "static" Calico manifests.
##########################################################################
if [[ $CALICO_VERSION != master ]]; then
echo "Replacing image versions for static manifests"
	for img in $NON_HELM_MANIFEST_IMAGES; do
		curr_img=${defaultRegistry}/${img}
		new_img=${REGISTRY}/${img}
		echo "$curr_img:$defaultCalicoVersion --> $new_img:$CALICO_VERSION"
		find . -type f -exec sed -i "s|${curr_img}:[A-Za-z0-9_.-]*|${new_img}:$CALICO_VERSION|g" {} \;
	done
fi
