---
title: Create cluster roles for Windows nodes
description: Configure cluster roles with correct permissions for Calico for Windows.
canonical_url: '/getting-started/windows-calico/cluster-roles'
---

### Big picture

Create cluster role for Windows nodes.

### How to

Because Kubernetes on Windows cannot run {{site.prodname}} in a pod with an auto-provisioned service account, {{site.prodname}} requires a kubeconfig file to access the API server. This section describes how to create an appropriate service account, and then to export the service account token as a kubeconfig file for {{site.prodname}} to use.

>**Note**: In general, the node kubeconfig as used by kubelet does not have enough permissions to access {{site.prodname}}-specific resources.
{: .alert .alert-info}

#### Install the cluster-role manifest

A cluster-role with the correct permissions for {{site.prodNameWindows}} is available here: [calico-windows cluster role](https://github.com/projectcalico/calico/releases/download/v3.16.0/win-cluster-role.yaml).

Apply the cluster role.

```
$ kubectl apply -f
```
  
Then, to make the kube-config file, you'll need the URL of your Kubernetes API server.

>**Note**: Kubernetes for Windows does not support access to services from the host so you must use the address of your server, not the Kubernetes service IP.
{: .alert .alert-info}

Set a variable to the URL of your API server:

```
$ server=https://<server>:<port>
```
Then, find the secret containing the service account token for the calico-windows service account:

```
$ kubectl get secret -n kube-system | grep calico-windows
```
Inspect the output and find the name of the token, store it in a variable:

```
$ name=calico-windows-token-xxxxx
```
Extract the parts of the secret, storing them in variables:

```
$ ca=$(kubectl get secret/$name -o jsonpath='{.data.ca\.crt}' -n
kube-system)

$ token=$(kubectl get secret/$name -o jsonpath='{.data.token}' -n
kube-system | base64 --decode)

$ namespace=$(kubectl get secret/$name -o jsonpath='{.data.namespace}'
-n kube-system | base64 --decode)
```
Then, output the file:

```
cat <<EOF > calico-config
apiVersion: v1
kind: Config
clusters:
- name: kubernetes
cluster:
certificate-authority-data: ${ca}
server: ${server}
contexts:
- name: calico-windows@kubernetes
context:
cluster: kubernetes
namespace: kube-system
user: calico-windows
current-context: calico-windows@kubernetes
users:
- name: calico-windows
user:
token: ${token}
EOF
```
Copy this config file to the windows node `C:\CalicoWindows\calico-kube-config` and set the KUBECONFIG environment variable in `config.ps1` to point to it.
