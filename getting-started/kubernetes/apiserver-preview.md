---
title: Try out the Calico API server tech-preview
description: Install the Calico API server on an existing Calico cluster
canonical_url: '/getting-started/kubernetes/quickstart'
---

### Big picture

[ **Feature status**: Tech-preview in v3.19 ]

Install the Calico API server on an existing cluster to enable management of Calico APIs using kubectl.

> **Warning!** The Calico API server is a tech preview feature and should not be used in production clusters. It has had limited testing and is liable to change in future releases. Please provide feedback and issue reports via GitHub.
{: .alert .alert-danger }

### Value

Normally, calicoctl is required in order to manage Calico APIs in the `projectcalico.org/v3` API group. The API server provides a REST API for Calico, and allows management of these APIs using kubectl instead.

### Before you begin

- A cluster with Calico installed using the Kubernetes API data store.

- A machine with `openssl` installed.

### Concepts

#### calicoctl vs kubectl

In previous releases, calicoctl has been required to manage Calico API resources in the `projectcalico.org/v3` API group. The calicoctl CLI tool provides important validation and defaulting on these APIs. The Calico API server performs
that defaulting and validation server-side, exposing the same API semantics without a dependency on calicoctl.

calicoctl is still required for the following subcommands:

- [calicoctl node]({{site.baseurl}}/reference/calicoctl/node)
- [calicoctl ipam]({{site.baseurl}}/reference/calicoctl/ipam)
- [calicoctl convert]({{site.baseurl}}/reference/calicoctl/convert)
- [calicoctl version]({{site.baseurl}}/reference/calicoctl/version)

### How to

#### Install the API server

1. Create the following manifest, which will install the API server as a deployment in the `calico-apiserver` namespace.

   ```
   kubectl create -f {{ "/manifests/apiserver.yaml" | absolute_url }}
   ```

   You will notice that the API server remains in a `ContainerCreating` state, as it is waiting for credentials to be provided for authenticating the main Kubernetes API server.

1. Generate a private key and CA bundle using the following openssl command. This certificate will be used by the main API server to authenticate with the Calico API server.

   ```
   openssl req -x509 -nodes -newkey rsa:4096 -keyout apiserver.key -out apiserver.crt -days 365 -subj '/CN=calico-api.calico-apiserver.svc' 
   ```

1. Provide the key and certificate to the Calico API server as a Kubernetes secret.

   ```
   kubectl create secret -n calico-apiserver generic calico-apiserver-certs --from-file=apiserver.key --from-file=apiserver.crt
   ```

1. Configure the main API server with the CA bundle.

   {% raw %}
   ```
   kubectl patch apiservice v3.projectcalico.org -p \
       "{\"spec\": {\"caBundle\": \"$(kubectl get secret -n calico-apiserver calico-apiserver-certs -o go-template='{{ index .data "apiserver.crt" }}')\"}}"
   ```
   {% endraw %}

   You should see the API server pod become ready, and Calico API resources become available. You can check whether the APIs are available with the following command:

   ```
   kubectl api-resources | grep '\sprojectcalico.org'
   ```

   You should see the following output:

   ```
   bgpconfigurations                 bgpconfig,bgpconfigs                            projectcalico.org              false        BGPConfiguration
   bgppeers                                                                          projectcalico.org              false        BGPPeer
   clusterinformations               clusterinfo                                     projectcalico.org              false        ClusterInformation
   felixconfigurations               felixconfig,felixconfigs                        projectcalico.org              false        FelixConfiguration
   globalnetworkpolicies             gnp,cgnp,calicoglobalnetworkpolicies            projectcalico.org              false        GlobalNetworkPolicy
   globalnetworksets                                                                 projectcalico.org              false        GlobalNetworkSet
   hostendpoints                     hep,heps                                        projectcalico.org              false        HostEndpoint
   ippools                                                                           projectcalico.org              false        IPPool
   kubecontrollersconfigurations                                                     projectcalico.org              false        KubeControllersConfiguration
   networkpolicies                   cnp,caliconetworkpolicy,caliconetworkpolicies   projectcalico.org              true         NetworkPolicy
   networksets                       netsets                                         projectcalico.org              true         NetworkSet
   profiles                                                                          projectcalico.org              false        Profile
   ```

> **Note:** kubectl may continue to prefer the crd.projectcalico.org API group due to the way it caches APIs locally. You can force kubectl to update
>           by removing its cache directory for your cluster. By default, the cache is located in `$(HOME)/.kube/cache`.
{: .alert .alert-info}

#### Use kubectl for projectcalico.org APIs

Once the API server has been installed, you can use kubectl to interact with the Calico APIs. For example, you can view and edit IP pools.

   ```
   kubectl get ippools
   ```

You should see output that looks like this:

   ```
   NAME                  CREATED AT
   default-ipv4-ippool   2021-03-19T16:47:12Z 
   ```

#### Uninstall the Calico API server

To uninstall, delete the API server manifest.

   ```
   kubectl delete -f {{site.baseurl}}/manifests/apiserver.yaml
   ```

Once removed, you will need to use calicoctl to manage projectcalico.org/v3 APIs.

### Next steps

**Recommended tutorials**
- [Secure a simple application using the Kubernetes NetworkPolicy API](../../security/tutorials/kubernetes-policy-basic)
- [Control ingress and egress traffic using the Kubernetes NetworkPolicy API](../../security/tutorials/kubernetes-policy-advanced)
- [Run a tutorial that shows blocked and allowed connections in real time](../../security/tutorials/kubernetes-policy-demo/kubernetes-demo)
