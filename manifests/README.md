# Calico manifests

This directory contains manifests for installing Calico on Kubernetes in various ways.

The majority of the manifests in this directory are automatically generated from the helm charts
in the `charts/` directory of this repository, and can be updated by running `make gen-manifests`
in the repository root.

To make changes to the auto-generated manifests:

1. Modify the source content in either `charts/tigera-operator/` or `charts/calico` 

2. Re-run code generation from the top level of this repository

   ```
   make gen-manifests
   ```

Some of these manifests are not automatically generated. To edit these, modify the manifests directly and 
commit your changes. **The following manifests are not auto generated:**

- alp/istio-inject-configmap-X.yaml
- apiserver.yaml
- calico-windows-bgp.yaml
- calico-windows-vxlan.yaml
- calicoctl-etcd.yaml
- calicoctl.yaml
- canal-etcd.yaml
- canal.yaml
- csi-driver.yaml
- custom-resources.yaml
- flannel-migration/migration-job.yaml
- grafana-dashboards.yaml
- ocp/00-namespace-tigera-operator.yaml
- ocp/01-cr-apiserver.yaml
- ocp/01-cr-installation.yaml
- ocp-tigera-operator-no-resource-loading.yaml
- operator-crds.yaml
- windows-kube-proxy.yaml
