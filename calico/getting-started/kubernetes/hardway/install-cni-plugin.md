---
title: Install CNI plugin
description: Steps to install the Calico Container Network Interface (CNI)
canonical_url: '/getting-started/kubernetes/hardway/install-cni-plugin'
---

Kubernetes uses the Container Network Interface (CNI) to interact with networking providers like {{site.prodname}}.
The {{site.prodname}} binary that presents this API to Kubernetes is called the **CNI plugin** and must be installed
on every node in the Kubernetes cluster.

To understand how the Container Network Interface (CNI) works with Kubernetes, and how it enhances Kubernetes networking, read our {% include open-new-window.html text='Kubernetes CNI guide' url='https://www.tigera.io/learn/guides/kubernetes-networking/kubernetes-cni/' %}.

## Provision Kubernetes user account for the plugin

The CNI plugin interacts with the Kubernetes API server while creating pods, both to obtain additional information
and to update the datastore with information about the pod.

On the Kubernetes master node, create a key for the CNI plugin to authenticate with and certificate signing request.

```bash
openssl req -newkey rsa:4096 \
           -keyout cni.key \
           -nodes \
           -out cni.csr \
           -subj "/CN=calico-cni"
```

We will sign this certificate using the main Kubernetes CA.

```bash
sudo openssl x509 -req -in cni.csr \
                  -CA /etc/kubernetes/pki/ca.crt \
                  -CAkey /etc/kubernetes/pki/ca.key \
                  -CAcreateserial \
                  -out cni.crt \
                  -days 365
sudo chown $(id -u):$(id -g) cni.crt
```

Next, we create a kubeconfig file for the CNI plugin to use to access Kubernetes. Copy this `cni.kubeconfig` file **to every node** in the cluster.

```bash
APISERVER=$(kubectl config view -o jsonpath='{.clusters[0].cluster.server}')
kubectl config set-cluster kubernetes \
    --certificate-authority=/etc/kubernetes/pki/ca.crt \
    --embed-certs=true \
    --server=$APISERVER \
    --kubeconfig=cni.kubeconfig

kubectl config set-credentials calico-cni \
    --client-certificate=cni.crt \
    --client-key=cni.key \
    --embed-certs=true \
    --kubeconfig=cni.kubeconfig

kubectl config set-context default \
    --cluster=kubernetes \
    --user=calico-cni \
    --kubeconfig=cni.kubeconfig

kubectl config use-context default --kubeconfig=cni.kubeconfig
```

## Provision RBAC

Define a cluster role the CNI plugin will use to access Kubernetes.

```bash
kubectl apply -f - <<EOF
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: calico-cni
rules:
  # The CNI plugin needs to get pods, nodes, and namespaces.
  - apiGroups: [""]
    resources:
      - pods
      - nodes
      - namespaces
    verbs:
      - get
  # The CNI plugin patches pods/status.
  - apiGroups: [""]
    resources:
      - pods/status
    verbs:
      - patch
 # These permissions are required for Calico CNI to perform IPAM allocations.
  - apiGroups: ["crd.projectcalico.org"]
    resources:
      - blockaffinities
      - ipamblocks
      - ipamhandles
    verbs:
      - get
      - list
      - create
      - update
      - delete
  - apiGroups: ["crd.projectcalico.org"]
    resources:
      - ipamconfigs
      - clusterinformations
      - ippools
    verbs:
      - get
      - list
EOF
```

Bind the cluster role to the `calico-cni` account.

```bash
kubectl create clusterrolebinding calico-cni --clusterrole=calico-cni --user=calico-cni
```

## Install the plugin

**Do these steps on each node in your cluster**.

Run these commands as root.

```bash
sudo su
```

Install the CNI plugin Binaries

```bash
curl -L -o /opt/cni/bin/calico https://github.com/projectcalico/cni-plugin/releases/download/v3.14.0/calico-amd64
chmod 755 /opt/cni/bin/calico
curl -L -o /opt/cni/bin/calico-ipam https://github.com/projectcalico/cni-plugin/releases/download/v3.14.0/calico-ipam-amd64
chmod 755 /opt/cni/bin/calico-ipam
```

Create the config directory

```bash
mkdir -p /etc/cni/net.d/
```

Copy the kubeconfig from the previous section
```bash
cp cni.kubeconfig /etc/cni/net.d/calico-kubeconfig
chmod 600 /etc/cni/net.d/calico-kubeconfig
```

Write the CNI configuration
```bash
cat > /etc/cni/net.d/10-calico.conflist <<EOF
{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "calico",
      "log_level": "info",
      "datastore_type": "kubernetes",
      "mtu": 1500,
      "ipam": {
          "type": "calico-ipam"
      },
      "policy": {
          "type": "k8s"
      },
      "kubernetes": {
          "kubeconfig": "/etc/cni/net.d/calico-kubeconfig"
      }
    },
    {
      "type": "portmap",
      "snat": true,
      "capabilities": {"portMappings": true}
    }
  ]
}
EOF
```

Exit from su and go back to the logged in user.

```bash
exit
```

At this point Kubernetes nodes will become `Ready` because Kubernetes has a networking provider and configuration installed.

```bash
kubectl get nodes
```

## Next

[Install Typha](./install-typha)
