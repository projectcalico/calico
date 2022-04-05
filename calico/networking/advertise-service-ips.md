---
title: Advertise Kubernetes service IP addresses
description: Configure Calico to advertise Kubernetes service cluster IPs and external IPs outside the cluster using BGP.
---

### Big picture

Enable {{site.prodname}} to advertise Kubernetes service IPs outside a cluster. {{site.prodname}} supports advertising a service’s cluster IPs and external IPs.

### Value

Typically, Kubernetes service cluster IPs are accessible only within the cluster, so external access to the service requires a dedicated load balancer or ingress controller. In cases where a service’s cluster IP is not routable, the service can be accessed using its external IP.

Just as {{site.prodname}} supports advertising **pod IPs** over BGP, it also supports advertising Kubernetes **service IPs** outside a cluster over BGP. This avoids the need for a dedicated load balancer. This feature also supports equal cost multi-path (ECMP) load balancing across nodes in the cluster, as well as source IP address preservation for local services when you need more control.

### Features

This how-to guide uses the following {{site.prodname}} features:

**Advertise service cluster and external IP addresses**:

- **BGPConfiguration** resource with `serviceClusterIPs` and `serviceExternalIPs` fields

### Concepts

#### BGP makes it easy

In Kubernetes, all requests for a service are redirected to an appropriate endpoint (pod) backing that service. Because {{site.prodname}} uses BGP, external traffic can be routed directly to Kubernetes services by advertising Kubernetes service IPs into the BGP network.

If your deployment is configured to peer with BGP routers outside the cluster, those routers (plus any other upstream places the routers propagate to) can send traffic to a Kubernetes service IP for routing to one of the available endpoints for that service.

#### Advertising service IPs: quick glance

{{site.prodname}} implements the Kubernetes **externalTrafficPolicy** using kube-proxy to direct incoming traffic to a correct pod. Advertisement is handled differently based on the service type that you configure for your service.

| **Service mode**  | **Cluster IP advertisement**                                 | **Traffic is...**                                            | Source IP address is... |
| ----------------- | ------------------------------------------------------------ | ------------------------------------------------------------ | ----------------------- |
| Cluster (default) | All nodes in the cluster statically advertise a route to the service CIDR. | Load balanced across nodes in the cluster using ECMP, then forwarded to appropriate pod in the service using SNAT. May incur second hop to another node, but good overall load balancing. | Obscured by SNAT        |
| Local             | The nodes with a pod backing the service advertise a specific route (/32 or /128) to the service's IP. | Load balanced across nodes with endpoints for the service.  Avoids second hop for LoadBalancer and NodePort type services, traffic may be unevenly load balanced. (Other traffic is load balanced across nodes in the cluster.) | Preserved               |


If your {{site.prodname}} deployment is configured to peer with BGP routers outside the cluster, those routers - plus any further upstream places that those routers propagate to - will be able to send traffic to a Kubernetes service cluster IP, and that traffic is routed to one of the available endpoints for that service.

#### Tips for success

- Generally, we recommend using “Local” for the following reasons:
  - If any of your network policy uses rules to match by specific source IP addresses, using Local is the obvious choice because the source IP address is not altered, and the policy will still work.
  - Return traffic is routed directly to the source IP because “Local” services do not require undoing the source NAT (unlike “Cluster” services).
- Cluster IP advertisement works best with a ToR that supports ECMP. Otherwise, all traffic for a given route is directed to a single node.

### Before you begin...

**Required**
- [Configure BGP peering]({{site.baseurl}}/networking/bgp) between {{site.prodname}} and your network infrastructure
- For ECMP load balancing to services, the upstream routers must be configured to use BGP multipath.
- You need at least one external node outside the cluster that acts as a router, route reflector, or ToR that is peered with calico nodes inside the cluster.
- Services must be configured with the correct service mode (“Cluster” or “Local”) for your implementation. For `externalTrafficPolicy: Local`, the service must be type `LoadBalancer` or `NodePort`.

**Limitations**
- OpenShift, versions 4.5 and 4.6  
    There is a {% include open-new-window.html text='bug' url='https://github.com/kubernetes/kubernetes/issues/91374' %} where the source IP is not preserved by NodePort services or traffic via a Service ExternalIP with externalTrafficPolicy:Local.   
    
   OpenShift users on v4.5 or v4.6 can use this {% include open-new-window.html text='workaround to avoid SNAT with ExternalIP' url='https://docs.openshift.com/container-platform/4.7/nodes/clusters/nodes-cluster-enabling-features.html' %}:

   ```
     oc edit featuregates.config.openshift.io cluster
      spec:
        customNoUpgrade:
          enabled:
          - ExternalPolicyForExternalIP
   ```
   Kubernetes users on version v1.18 or v1.19 can enable source IP preservation for NodePort services using the ExternalPolicyForExternalIP feature gate. 

   Source IP preservation for NodePort and services and ExternalIPs is enabled by default in OpenShift v4.7+, and Kubernetes v1.20+. 

### How to

- [Advertise service cluster IP addresses](#advertise-service-cluster-ip-addresses)
- [Advertise service external IP addresses](#advertise-service-external-ip-addresses)
- [Advertise service load balancer IP addresses](#advertise-service-load-balancer-ip-addresses)
- [Exclude certain nodes from advertisement](#exclude-certain-nodes-from-advertisement)

#### Advertise service cluster IP addresses

1. Determine the service cluster IP range.  (Or ranges, if your cluster is [dual stack]({{site.baseurl}}/networking/ipv6).)

   The range(s) for your cluster can be inferred from the `--service-cluster-ip-range` option passed to the Kubernetes API server. For help, see the {% include open-new-window.html text='Kubernetes API server reference guide' url='https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/' %}.

1. Check to see if you have a default BGPConfiguration.

   ```bash
   calicoctl get bgpconfig default
   ```

1. Based on above results, update or create a BGPConfiguration.

   **Update default BGPConfiguration**
   Patch the BGPConfiguration using the following command, using your own service cluster IP CIDR in place of "10.0.0.0/24":

   ```bash
   calicoctl patch bgpconfig default --patch \
      '{"spec": {"serviceClusterIPs": [{"cidr": "10.0.0.0/24"}]}}'
   ```

   **Create default BGPConfiguration**
   Use the following sample command to create a default BGPConfiguration. Add your CIDR blocks, covering the cluster IPs to be advertised, in the `serviceClusterIPs` field, for example:

   ```bash
   calicoctl create -f - <<EOF
   apiVersion: projectcalico.org/v3
   kind: BGPConfiguration
   metadata:
     name: default
   spec:
     serviceClusterIPs:
     - cidr: 10.96.0.0/16
     - cidr: fd00:1234::/112
   EOF
   ```

   For help see, [BGP configuration resource]({{site.baseurl}}/reference/resources/bgpconfig).

> **Note**: In earlier versions of {{site.prodname}}, and for IPv4 only, service cluster IP advertisement was configured via the environment variable CALICO_ADVERTISE_CLUSTER_IPS.
> That environment variable takes precedence over any serviceClusterIPs configured in the default BGPConfiguration. We recommend replacing the
> deprecated CALICO_ADVERTISE_CLUSTER_IPS with BGPConfiguration.
{: .alert .alert-info}

#### Advertise service external IP addresses

1. Identify the external IP ranges of all services that you want to advertise outside of the {{site.prodname}} cluster.

1. Check to see if you have a default BGPConfiguration.

   ```bash
   calicoctl get bgpconfig default
   ```

1. Based on above results, update or create a BGPConfiguration.

   **Update default BGPConfiguration**
   Patch the BGPConfiguration using the following command, adding your own service external IP CIDRs:

   ```bash
   calicoctl patch bgpconfig default --patch \
      '{"spec": {"serviceExternalIPs": [{"cidr": "x.x.x.x"}, {"cidr": "y.y.y.y"}]}}'
   ```

   **Create default BGPConfiguration**
   Use the following sample command to create a default BGPConfiguration. Add your CIDR blocks for external IPs to be advertised in the `serviceExternalIPs` field.

   ```bash
   calicoctl create -f - <<EOF
   apiVersion: projectcalico.org/v3
   kind: BGPConfiguration
   metadata:
     name: default
   spec:
     serviceExternalIPs:
     - cidr: x.x.x.x/16
     - cidr: y.y.y.y/32
   EOF
   ```

   For help see, [BGP configuration resource]({{site.baseurl}}/reference/resources/bgpconfig).

#### Advertise service load balancer IP addresses

The following steps will configure {{site.prodname}} to advertise Service `status.LoadBalancer.Ingress.IP` addresses.

1. Identify the IP ranges to be used for Service LoadBalancer address allocation.

1. Check to see if you have a default BGPConfiguration.

   ```bash
   calicoctl get bgpconfig default
   ```

1. Based on above results, update or create a BGPConfiguration.

   **Update default BGPConfiguration**
   Patch the BGPConfiguration using the following command, adding your own service load balancer IP CIDRs:

   ```bash
   calicoctl patch bgpconfig default --patch '{"spec": {"serviceLoadBalancerIPs": [{"cidr": "x.x.x.x/16"}]}}'
   ```

   **Create default BGPConfiguration**
   Use the following sample command to create a default BGPConfiguration. Add your CIDR blocks for load balancer IPs to be advertised in the `serviceLoadBalancerIPs` field.

   ```bash
   calicoctl create -f - <<EOF
   apiVersion: projectcalico.org/v3
   kind: BGPConfiguration
   metadata:
     name: default
   spec:
     serviceLoadBalancerIPs:
     - cidr: x.x.x.x/16
   EOF
   ```

   For help see, [BGP configuration resource]({{site.baseurl}}/reference/resources/bgpconfig).

Service LoadBalancer address allocation is outside the current scope of {{site.prodname}}, but can be implemented with an external controller.
You can build your own, or use a third-party implementation like the MetalLB project.

To install the MetalLB controller for allocating addresses, perform the following steps.

1. Follow [the MetalLB documentation](https://metallb.universe.tf/installation/#installation-by-manifest) to install the `metallb-system/controller` resources.

   However, do not install the `metallb-system/speaker` component. The speaker component also attempts to establish BGP sessions on the node, and will conflict with Calico.

1. Configure MetalLB to provision addresses by creating the following config map, replacing `x.x.x.x/16` with the CIDR given to {{site.prodname}} in the steps above.

   ```
   kubectl create -f - <<EOF
   apiVersion: v1
   kind: ConfigMap
   metadata:
     namespace: metallb-system
     name: config
   data:
     config: |
       address-pools:
       - name: default
         protocol: bgp
         addresses:
         - x.x.x.x/16
   EOF
   ```

#### Exclude certain nodes from advertisement

In some cases, you may want to exclude certain nodes from advertising service addresses. For example, control plane nodes that do not host any services themselves.

To remove a node from service advertisement, apply the label `node.kubernetes.io/exclude-from-external-load-balancers=true`.

For example, to exclude the node `control-plane-01` from service advertisement, you can run the following command:

```
kubectl label node control-plane-01 node.kubernetes.io/exclude-from-external-load-balancers=true
```

### Tutorial

For a tutorial on how service advertisement works with {{site.prodname}}, see the blog {% include open-new-window.html text='Kubernetes Service IP Route Advertisement' url='https://www.projectcalico.org/kubernetes-service-ip-route-advertisement/' %}.

### Above and beyond

Other topics on creating network policy for Kubernetes services:

- [Apply policy to services exposed externally as cluster IPs]({{site.baseurl}}/security/services-cluster-ips)
- [Apply policy to Kubernetes node ports]({{site.baseurl}}/security/kubernetes-node-ports)
