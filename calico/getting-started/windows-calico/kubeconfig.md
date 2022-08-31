---
title: Create kubeconfig for Windows nodes
description: Configure kubeconfig for Calico for Windows.
canonical_url: '/getting-started/windows-calico/kubeconfig'
---

### Big picture

Create kubeconfig for Windows nodes for manual installations of {{site.prodnameWindows}}.

### How to

In a manual installation of {{site.prodnameWindows}}, {{site.prodname}} requires a kubeconfig file to access the API server. This section describes how to find an existing `calico-node` service account used by {{site.prodname}} on Linux side, and then to export the service account token as a kubeconfig file for {{site.prodname}} to use.

>**Note**: In general, the node kubeconfig as used by kubelet does not have enough permissions to access {{site.prodname}}-specific resources.
{: .alert .alert-info}

#### Export calico-node service account token as a kubeconfig file
  
>**Note**: If your Kubernetes version is v1.24.0 or higher, service account token secrets are no longer automatically created. Before continuing, {% include open-new-window.html text='manually create' url='https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#manually-create-a-service-account-api-token' %} the calico-node service account token:
```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: calico-node-token
  namespace: calico-system
  annotations:
    kubernetes.io/service-account.name: calico-node
type: kubernetes.io/service-account-token
EOF
```
Note: if {{site.prodname}} is installed in kube-system, update the `namespace` in the above command.
{: .alert .alert-info}

To make the kubeconfig file, you'll need the URL of your Kubernetes API server.

>**Note**: Kubernetes for Windows does not support access to services from the host so you must use the address of your server, not the Kubernetes service IP.
{: .alert .alert-info}

>**Note**: Use namespace `kube-system` instead of `calico-system` if your Calico installation is non operator-managed.
{: .alert .alert-info}

Set a variable to the URL of your API server:

```
$ server=https://<server>:<port>
```
Then, find the secret containing the service account token for the `calico-node` service account:

```
$ kubectl get secret -n calico-system | grep calico-node
```
Inspect the output and find the name of the token, store it in a variable:

```
$ name=calico-node-token-xxxxx
```
Extract the parts of the secret, storing them in variables:

```
$ ca=$(kubectl get secret/$name -o jsonpath='{.data.ca\.crt}' -n calico-system)

$ token=$(kubectl get secret/$name -o jsonpath='{.data.token}' -n calico-system | base64 --decode)

$ namespace=$(kubectl get secret/$name -o jsonpath='{.data.namespace}' -n calico-system | base64 --decode)
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
    namespace: calico-system
    user: calico-windows
current-context: calico-windows@kubernetes
users:
- name: calico-windows
  user:
    token: ${token}
EOF
```
Copy this config file to the windows node `{{site.rootDirWindows}}\calico-kube-config` and set the KUBECONFIG environment variable in `config.ps1` to point to it.
