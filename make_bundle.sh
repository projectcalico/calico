#!/bin/bash
set -ex

tar -cf manifests.tar \
-C manifests/ocp/crds 01-crd-installation.yaml 01-crd-tigerastatus.yaml \
-C $(pwd)/manifests/ocp/tigera-operator \
00-namespace-tigera-operator.yaml \
02-rolebinding-tigera-operator.yaml \
 02-role-tigera-operator.yaml \
 02-serviceaccount-tigera-operator.yaml \
 02-configmap-calico-resources.yaml \
 02-configmap-tigera-install-script.yaml \
 02-tigera-operator.yaml \
-C $(pwd)/manifests/ocp 01-cr-installation.yaml \
-C $(pwd)/manifests/ocp/crds/calico/kdd 02-crd-bgpconfiguration.yaml \
02-crd-bgppeer.yaml \
02-crd-blockaffinity.yaml \
02-crd-clusterinformation.yaml \
02-crd-felixconfiguration.yaml \
02-crd-globalnetworkpolicy.yaml \
02-crd-globalnetworkset.yaml \
02-crd-hostendpoint.yaml \
02-crd-ipamblock.yaml \
02-crd-ipamconfig.yaml \
02-crd-ipamhandle.yaml \
02-crd-ippool.yaml \
02-crd-kubecontrollersconfiguration.yaml \
02-crd-networkpolicy.yaml \
02-crd-networkset.yaml
