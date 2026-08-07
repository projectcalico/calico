# Configuration for a multi-node local kind cluster with the Calico authorization webhook.
#
# This mirrors kind.config, adding the AuthorizationConfiguration from webhooks/config/,
# which inserts the Calico tier-based RBAC webhook between Node and RBAC in the
# kube-apiserver authorization chain. Keep the non-authz parts in sync with kind.config.
#
# Usage: make kind-authz-cluster-create
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "192.168.0.0/16,fd00:10:244::/64"
  ipFamily: dual
  dnsSearch: []

nodes:
- role: control-plane
  extraMounts:
  - hostPath: __REPO_ROOT__/hack/test/kind/authz-webhook-config
    containerPath: /authz-webhook-config
    readOnly: true
  kubeadmConfigPatches:
  - |
    apiVersion: kubeadm.k8s.io/v1beta3
    kind: ClusterConfiguration
    metadata:
      name: config
    apiServer:
      extraArgs:
        authorization-config: /etc/kubernetes/authz/authorization-configuration.yaml
      extraVolumes:
      - name: authz-webhook-config
        hostPath: /authz-webhook-config
        mountPath: /etc/kubernetes/authz
        readOnly: true
        pathType: DirectoryOrCreate
- role: worker
- role: worker
- role: worker

featureGates:
  "MutatingAdmissionPolicy": true

runtimeConfig:
  "admissionregistration.k8s.io/v1beta1": "true"

# Note: containerd in kind reads per-host config from /etc/containerd/certs.d/.
# registry.sh writes the localhost:5000 -> http://kind-registry:5000 mapping
# to each node after cluster creation; the older containerdConfigPatches
# `mirrors` syntax is rejected when config_path is set.

kubeadmConfigPatches:
- |
  apiVersion: kubeadm.k8s.io/v1beta3
  kind: ClusterConfiguration
  metadata:
    name: config
  controllerManager:
    extraArgs:
      cluster-cidr: "192.168.0.0/16"
- |
  apiVersion: kubeproxy.config.k8s.io/v1alpha1
  kind: KubeProxyConfiguration
  metadata:
    name: config
  mode: ipvs
  conntrack:
    maxPerCore: 0
