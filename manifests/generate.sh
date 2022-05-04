#!/bin/bash

# This script updates the manifsts in this directory using helm.
# Values files for the manifests in this directory can be found in 
# ../calico/charts/values.

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

helm -n tigera-operator template \
	--include-crds \
	../charts/tigera-operator \
	-f ../charts/values/tigera-operator.yaml >> tigera-operator.yaml

##########################################################################
# Build CRD manifest.
#
# This manifest is used in "Calico the hard way" documentation.
##########################################################################
echo "# CustomResourceDefinitions for Calico the Hard Way" > crds.yaml
for FILE in $(ls ../charts/calico/crds); do
	helm template ../charts/calico \
		--include-crds \
		--show-only $FILE \
		-f ../charts/values/calico.yaml \
		-f ../charts/values/values.common.yaml >> crds.yaml
done

##########################################################################
# Build Calico manifests.
#
# To add a new manifest to this directory, define
# a values file in ../charts/values/ and then add it to VALUES_FILES.
##########################################################################
VALUES_FILES="calico-typha.yaml
	calico-bpf.yaml
	calico-vxlan.yaml
	calico.yaml
	calico-etcd.yaml 
	calico-policy-only.yaml
	flannel-migration/calico.yaml
	"

for FILE in $VALUES_FILES; do
	helm -n kube-system template \
		../charts/calico \
		-f ../charts/values/$FILE \
		-f ../charts/values/values.common.yaml > $FILE
done
