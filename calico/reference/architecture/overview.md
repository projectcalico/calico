---
title: Component architecture
description: Learn the basic Calico components.
canonical_url: '/reference/architecture/overview'
---

### {{site.prodname}} components

The following diagram shows the required and optional {{site.prodname}} components for a Kubernetes, on-premises deployment with networking and network policy.

![calico-components]({{site.baseurl}}/images/architecture-calico.svg)

**{{site.prodname}} components**

 - [Calico API server](#calico-api-server)
 - [Felix](#felix)
 - [BIRD](#bird)
 - [confd](#confd)
 - [Dikastes](#dikastes)
 - [CNI plugin](#cni-plugin)
 - [Datastore plugin](#datastore-plugin)
 - [IPAM plugin](#ipam-plugin)
 - [kube-controllers](#kube-controllers)
 - [Typha](#typha)
 - [calicoctl](#calicoctl)

**Cloud orchestrator plugins**

 - [Plugins for cloud orchestrators](#plugins-for-cloud-orchestrators)

### Calico API server

**Main task**: Lets you manage {{site.prodname}} resources directly with `kubectl`.

### Felix

**Main task**: Programs routes and ACLs, and anything else required on the host to provide desired connectivity for the endpoints on that host. Runs on each machine that hosts endpoints. Runs as an agent daemon. [Felix resource]({{site.baseurl}}/reference/resources/felixconfig).

Depending on the specific orchestrator environment, Felix is responsible for:

- **Interface management**

    Programs information about interfaces into the kernel so the kernel can correctly handle the traffic from that endpoint. In particular, it ensures that the host responds to ARP requests from each workload with the MAC of the host, and enables IP forwarding for interfaces that it manages. It also monitors interfaces to ensure that the programming is applied at the appropriate time.

- **Route programming**

    Programs routes to the endpoints on its host into the Linux kernel FIB (Forwarding Information Base). This ensures that packets destined for those endpoints that arrive on at the host are forwarded accordingly.

- **ACL programming**

    Programs ACLs into the Linux kernel to ensure that only valid traffic can be sent between endpoints, and that endpoints cannot circumvent {{site.prodname}} security measures.

- **State reporting**

    Provides network health data. In particular, it reports errors and problems when configuring its host. This data is written to the datastore so it visible to other components and operators of the network.

> **Note**: `{{site.nodecontainer}}` can be run in *policy only mode* where Felix runs without BIRD and confd. This provides policy management without route distribution between hosts, and is used for deployments like managed cloud providers. You enable this mode by setting the environment variable, `CALICO_NETWORKING_BACKEND=none` before starting the node.
{: .alert .alert-info}

### BIRD

**Main task**: Gets routes from Felix and distributes to BGP peers on the network for inter-host routing. Runs on each node that hosts a Felix agent. Open source, internet routing daemon. [BIRD]({{site.baseurl}}/reference/node/configuration#content-main).

The BGP client is responsible for:

- **Route distribution**

    When Felix inserts routes into the Linux kernel FIB, the BGP client distributes them to other nodes in the deployment. This ensures efficient traffic routing for the deployment.

- **BGP route reflector configuration**

    BGP route reflectors are often configured for large deployments rather than a standard BGP client. BGP route reflectors acts as a central point for connecting BGP clients. (Standard BGP requires that every BGP client be connected to every other BGP client in a mesh topology, which is difficult to maintain.)

    For redundancy, you can seamlessly deploy multiple BGP route reflectors. BGP route reflectors are involved only in control of the network: no endpoint data passes through them. When the {{site.prodname}} BGP client advertises routes from its FIB to the route reflector, the route reflector advertises those routes out to the other nodes in the deployment.

### confd

**Main task**: Monitors {{site.prodname}} datastore for changes to BGP configuration and global defaults such as AS number, logging levels, and IPAM information. Open source, lightweight configuration management tool. 

Confd dynamically generates BIRD configuration files based on the updates to data in the datastore. When the configuration file changes, confd triggers BIRD to load the new files. [Configure confd]({{site.baseurl}}/reference/node/configuration#content-main), and {% include open-new-window.html text='confd project' url='https://github.com/kelseyhightower/confd' %}.


### Dikastes

**Main task**: Enforces network policy for Istio service mesh. Runs on a cluster as a sidecar proxy to Istio Envoy.

(Optional) {{site.prodname}} enforces network policy for workloads at both the Linux kernel (using iptables, L3-L4), and at L3-L7 using a Envoy sidecar proxy called Dikastes, with cryptographic authentication of requests. Using multiple enforcement points establishes the identity of the remote endpoint based on multiple criteria. The host Linux kernel enforcement protects your workloads even if the workload pod is compromised, and the Envoy proxy is bypassed.

> **Note**: Dikastes can be terminated by issuing an HTTP POST request to /terminate on the socket address specified using environment variables `DIKASTES_HTTP_BIND_ADDR` and `DIKASTES_HTTP_BIND_PORT`. This is to allow for graceful termination so that Kubernetes Jobs can complete successfully and is analogous to Envoy's /quitquitquit. eg. `curl -XPOST http://127.0.0.1:7777/terminate`
{: .alert .alert-info}
### CNI plugin

**Main task**: Provides {{site.prodname}} networking for Kubernetes clusters.

The {{site.prodname}} binary that presents this API to Kubernetes is called the CNI plugin, and must be installed on every node in the Kubernetes cluster. The {{site.prodname}} CNI plugin allows you to use {{site.prodname}} networking for any orchestrator that makes use of the CNI networking specification. Configured through the standard {% include open-new-window.html text='CNI configuration mechanism'
url='https://github.com/containernetworking/cni/blob/master/SPEC.md#network-configuration' %}, and [{{site.prodname}} CNI plugin]({{site.baseurl}}/reference/cni-plugin/configuration).


### Datastore plugin

**Main task**: Increases scale by reducing each node’s impact on the datastore. It is one of the {{site.prodname}} [CNI plugins]({{site.baseurl}}/reference/cni-plugin/configuration).

- **Kubernetes API datastore (kdd)**

   The advantages of using the Kubernetes API datastore (kdd) with {{site.prodname}} are:

   - Simpler to manage because it does not require an extra datastore
   - Use Kubernetes RBAC to control access to {{site.prodname}} resources
   - Use Kubernetes audit logging to generate audit logs of changes to {{site.prodname}} resources

- **etcd**

   `etcd` is a consistent, highly-available distributed key-value store that provides data storage for the {{site.prodname}} network, and for communications between components. `etcd` is supported for protecting only non-cluster hosts (as of {{site.prodname}} v3.1). For completeness, `etcd ` advantages are:

   - Lets you run {{site.prodname}} on non-Kubernetes platforms
   - Separation of concerns between Kubernetes and {{site.prodname}} resources, for example allowing you to scale the datastores independently
   - Lets you run a {{site.prodname}} cluster that contains more than just a single Kubernetes cluster, for example, bare metal servers with {{site.prodname}} host protection interworking with a Kubernetes cluster; or multiple Kubernetes clusters.

   {% include open-new-window.html text='etcd admin guide' url='https://coreos.com/etcd/docs/latest/admin_guide.html#optimal-cluster-size' %}

### IPAM plugin

**Main task**: Uses {{site.prodname}}’s IP pool resource to control how IP addresses are allocated to pods within the cluster. It is the default plugin used by most {{site.prodname}} installations. It is one of the {{site.prodname}} [CNI plugins]({{site.baseurl}}/reference/cni-plugin/configuration).


### kube-controllers

**Main task**: Monitors the Kubernetes API and performs actions based on cluster state. [kube-controllers]({{site.baseurl}}/reference/kube-controllers/configuration).

The `tigera/kube-controllers` container includes the following controllers:

- Policy controller
- Namespace controller
- Serviceaccount controller
- Workloadendpoint controller
- Node controller

### Typha

**Main task**: Increases scale by reducing each node’s impact on the datastore. Runs as a daemon between the datastore and instances of Felix. Installed by default, but not configured. {% include open-new-window.html text='Typha description' url='https://github.com/projectcalico/typha' %}, and [Typha component]({{site.baseurl}}/reference/typha/).

Typha maintains a single datastore connection on behalf of all of its clients like Felix and confd. It caches the datastore state and deduplicates events so that they can be fanned out to many listeners. Because one Typha instance can support hundreds of Felix instances, it reduces the load on the datastore by a large factor. And because Typha can filter out updates that are not relevant to Felix, it also reduces Felix’s CPU usage. In a high-scale (100+ node) Kubernetes cluster, this is essential because the number of updates generated by the API server scales with the number of nodes.

### calicoctl

**Main task**: Command line interface to create, read, update, and delete {{site.prodname}} objects. `calicoctl` command line is available on any host with network access to the {{site.prodname}} datastore as either a binary or a container. Requires separate installation. [calicoctl]({{site.baseurl}}/reference/calicoctl/).

### Plugins for cloud orchestrators

**Main task**: Translates the orchestrator APIs for managing networks to the {{site.prodname}} data-model and datastore.

For cloud providers, {{site.prodname}} has a separate plugin for each major cloud orchestration platform. This allows {{site.prodname}} to tightly bind to the orchestrator, so users can manage the {{site.prodname}} network using their orchestrator tools. When required, the orchestrator plugin provides feedback from the {{site.prodname}} network to the orchestrator. For example, providing information about Felix liveness, and marking specific endpoints as failed if network setup fails.
