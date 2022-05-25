#!/bin/bash

# This script updates the manifsts in this directory using helm.
# Values files for the manifests in this directory can be found in 
# ../calico/charts/values.

HELM=${HELM:-../bin/helm}

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
		-f ../charts/values/values.common.yaml \
		-f ../charts/values/calico.yaml >> crds.yaml
done

##########################################################################
# Build Calico manifests.
#
# To add a new manifest to this directory, define
# a new values file in ../charts/values/
##########################################################################
VALUES_FILES=$(cd ../charts/values && find . -type f -name "*.yaml" | grep -v values.common.yaml)

for FILE in $VALUES_FILES; do
	echo "Generating manifest from charts/values/$FILE"
	${HELM} -n kube-system template \
		../charts/calico \
		-f ../charts/values/values.common.yaml \
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
	--set apiServer.enabled=false
mv $(find ocp/tigera-operator -name "*.yaml") ocp/ && rm -r ocp/tigera-operator
