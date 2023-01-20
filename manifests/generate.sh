#!/bin/bash

# This script updates the manifsts in this directory using helm.
# Values files for the manifests in this directory can be found in 
# ../calico/charts/values.

# Helm binary to use. Default to the one installed by the Makefile.
HELM=${HELM:-../bin/helm}

# Get versions to install.
defaultCalicoVersion=$(cat ../charts/calico/values.yaml | grep version: | cut -d" " -f2)
CALICO_VERSION=${CALICO_VERSION:-$defaultCalicoVersion}

defaultOperatorVersion=$(cat ../charts/tigera-operator/values.yaml | grep version: | cut -d" " -f4)
OPERATOR_VERSION=${OPERATOR_VERSION:-$defaultOperatorVersion}

NON_HELM_MANIFEST_IMAGES="calico/apiserver calico/windows calico/ctl calico/csi calico/node-driver-registrar"

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
EOF

${HELM} -n tigera-operator template \
	--include-crds \
	--set installation.enabled=false \
	--set apiServer.enabled=false \
	--set tigeraOperator.version=$OPERATOR_VERSION \
	--set calicoctl.tag=$CALICO_VERSION \
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
${HELM} template --include-crds \
	-n tigera-operator \
	../charts/tigera-operator/ \
	--output-dir ocp \
	--set installation.kubernetesProvider=openshift \
	--set installation.enabled=false \
	--set apiServer.enabled=false \
	--set tigeraOperator.version=$OPERATOR_VERSION \
	--set calicoctl.tag=$CALICO_VERSION
# The first two lines are a newline and a yaml separator - remove them.
find ocp/tigera-operator -name "*.yaml" | xargs sed -i -e 1,2d
mv $(find ocp/tigera-operator -name "*.yaml") ocp/ && rm -r ocp/tigera-operator

##########################################################################
# Build Calico manifest used for in-repo testing. This is largely the same as the 
# one we ship, but with tweaked values.
##########################################################################
echo "Generating manifest from charts/values/$FILE"
${HELM} -n kube-system template \
	../charts/calico \
	-f ../node/tests/k8st/infra/values.yaml > ../node/tests/k8st/infra/calico-kdd.yaml

##########################################################################
# Replace image versions for "static" Calico manifests.
##########################################################################
if [[ $CALICO_VERSION != master ]]; then
echo "Replacing image versions for static manifests"
	for img in $NON_HELM_MANIFEST_IMAGES; do
		echo $img
		find . -type f -exec sed -i "s|$img:[A-Xa-z0-9_.-]*|$img:$CALICO_VERSION|g" {} \;
	done
fi
