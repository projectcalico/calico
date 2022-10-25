---
title: Secure Calico Prometheus endpoints
description: Limit access to Calico metric endpoints using network policy.
canonical_url: '/security/comms/secure-metrics'
---

## About securing access to {{site.prodname}}'s metrics endpoints

When using {{ site.prodname }} with Prometheus metrics enabled, we recommend using network policy
to limit access to {{ site.prodname }}'s metrics endpoints.

## Prerequisites

- {{site.prodname}} is installed with Prometheus metrics reporting enabled.
- `calicoctl` is [installed in your PATH and configured to access the data store](../../maintenance/clis/calicoctl/install).

## Choosing an approach

This guide provides two example workflows for creating network policies to limit access
to {{site.prodname}}'s Prometheus metrics. Choosing an approach depends on your requirements.

- [Using a deny-list approach](#using-a-deny-list-approach)

  This approach allows all traffic to your hosts by default, but lets you limit access to specific ports using
  {{site.prodname}} policy. This approach allows you to restrict access to specific ports, while leaving other
  host traffic unaffected.

- [Using an allow-list approach](#using-an-allow-list-approach)

  This approach denies traffic to and from your hosts by default, and requires that all
  desired communication be explicitly allowed by a network policy. This approach is more secure because
  only explicitly-allowed traffic will get through, but it requires you to know all the ports that should be open on the host.

## Using a deny-list approach

### Overview

The basic process is as follows:

1. Create a default network policy that allows traffic to and from your hosts.
1. Create host endpoints for each node that you'd like to secure.
1. Create a network policy that denies unwanted traffic to the {{site.prodname}} metrics endpoints.
1. Apply labels to allow access to the Prometheus metrics.

### Example for {{site.nodecontainer}}

This example shows how to limit access to the {{site.nodecontainer}} Prometheus metrics endpoints.

1. Create a default network policy to allow host traffic

   First, create a default-allow policy. Do this first to avoid a drop in connectivity when adding the host endpoints
   later, since host endpoints with no policy default to deny.

   To do this, create a file named `default-host-policy.yaml` with the following contents.

   ```yaml
   apiVersion: projectcalico.org/v3
   kind: GlobalNetworkPolicy
   metadata:
     name: default-host
   spec:
     # Select all {{site.prodname}} nodes.
     selector: running-calico == "true"
     order: 5000
     ingress:
     - action: Allow
     egress:
     - action: Allow
   ```

   Then, use `calicoctl` to apply this policy.

   ```bash
   calicoctl apply -f default-host-policy.yaml
   ```

1. List the nodes on which {{site.prodname}} is running with the following command.

   ```bash
   calicoctl get nodes
   ```

   In this case, we have two nodes in the cluster.

   ```
   NAME
   kubeadm-master
   kubeadm-node-0
   ```
   {: .no-select-button}

1. Create host endpoints for each {{site.prodname}} node.

   Create a file named `host-endpoints.yaml` containing a host endpoint for each node listed
   above. In this example, the contents would look like this.

   ```yaml
   apiVersion: projectcalico.org/v3
   kind: HostEndpoint
   metadata:
     name: kubeadm-master.eth0
     labels:
       running-calico: "true"
   spec:
     node: kubeadm-master
     interfaceName: eth0
     expectedIPs:
     - 10.100.0.15
   ---
   apiVersion: projectcalico.org/v3
   kind: HostEndpoint
   metadata:
     name: kubeadm-node-0.eth0
     labels:
       running-calico: "true"
   spec:
     node: kubeadm-node-0
     interfaceName: eth0
     expectedIPs:
     - 10.100.0.16
   ```

   In this file, replace `eth0` with the desired interface name on each node, and populate the
   `expectedIPs` section with the IP addresses on that interface.

   Note the use of a label to indicate that this host endpoint is running {{site.prodname}}. The
   label matches the selector of the network policy created in step 1.

   Then, use `calicoctl` to apply the host endpoints with the following command.

   ```bash
   calicoctl apply -f host-endpoints.yaml
   ```

1. Create a network policy that restricts access to the {{site.nodecontainer}} Prometheus metrics port.

   Now let's create a network policy that limits access to the Prometheus metrics port such that
   only endpoints with the label `calico-prometheus-access: true` can access the metrics.

   To do this, create a file named `calico-prometheus-policy.yaml` with the following contents.

   ```yaml
   # Allow traffic to Prometheus only from sources that are
   # labeled as such, but don't impact any other traffic.
   apiVersion: projectcalico.org/v3
   kind: GlobalNetworkPolicy
   metadata:
     name: restrict-calico-node-prometheus
   spec:
     # Select all {{site.prodname}} nodes.
     selector: running-calico == "true"
     order: 500
     types:
     - Ingress
     ingress:
     # Deny anything that tries to access the Prometheus port
     # but that doesn't match the necessary selector.
     - action: Deny
       protocol: TCP
       source:
         notSelector: calico-prometheus-access == "true"
       destination:
         ports:
         - 9091
   ```

   This policy selects all endpoints that have the label `running-calico: true`, and enforces a single ingress deny rule.
   The ingress rule denies traffic to port 9091 unless the source of traffic has the label `calico-prometheus-access: true`, meaning
   all {{site.prodname}} workload endpoints, host endpoints, and global network sets that do not have the label, as well as any
   other network endpoints unknown to {{site.prodname}}.

   Then, use `calicoctl` to apply this policy.

   ```bash
   calicoctl apply -f calico-prometheus-policy.yaml
   ```

1. Apply labels to any endpoints that should have access to the metrics.

   At this point, only endpoints that have the label `calico-prometheus-access: true` can reach
   {{site.prodname}}'s Prometheus metrics endpoints on each node. To grant access, simply add this label to the
   desired endpoints.

   For example, to allow access to a Kubernetes pod you can run the following command.

   ```bash
   kubectl label pod my-prometheus-pod calico-prometheus-access=true
   ```

   If you would like to grant access to a specific IP network, you
   can create a [global network set](../../reference/resources/globalnetworkset) using `calicoctl`.

   For example, you might want to grant access to your management subnets.

   ```yaml
   apiVersion: projectcalico.org/v3
   kind: GlobalNetworkSet
   metadata:
     name: calico-prometheus-set
     labels:
       calico-prometheus-access: "true"
   spec:
     nets:
     - 172.15.0.0/24
     - 172.101.0.0/24
   ```

### Additional steps for Typha deployments

If your {{site.prodname}} installation uses the Kubernetes API datastore and has greater than 50 nodes, it is likely
that you have installed Typha. This section shows how to use an additional network policy to secure the Typha
Prometheus endpoints.

After following the steps above, create a file named `typha-prometheus-policy.yaml` with the following contents.

```yaml
# Allow traffic to Prometheus only from sources that are
# labeled as such, but don't impact any other traffic.
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: restrict-calico-node-prometheus
spec:
  # Select all {{site.prodname}} nodes.
  selector: running-calico == "true"
  order: 500
  types:
  - Ingress
  ingress:
  # Deny anything that tries to access the Prometheus port
  # but that doesn't match the necessary selector.
  - action: Deny
    protocol: TCP
    source:
      notSelector: calico-prometheus-access == "true"
    destination:
      ports:
      - 9093
```

This policy selects all endpoints that have the label `running-calico: true`, and enforces a single ingress deny rule.
The ingress rule denies traffic to port 9093 unless the source of traffic has the label `calico-prometheus-access: true`, meaning
all {{site.prodname}} workload endpoints, host endpoints, and global network sets that do not have the label, as well as any
other network endpoints unknown to {{site.prodname}}.

Then, use `calicoctl` to apply this policy.

```bash
calicoctl apply -f typha-prometheus-policy.yaml
```
### Example for kube-controllers

If your {{site.prodname}} installation exposes metrics from kube-controllers, you can limit access to those metrics
with the following network policy.

Create a file named `kube-controllers-prometheus-policy.yaml` with the following contents.

```yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: restrict-kube-controllers-prometheus
  namespace: calico-system
spec:
  # Select kube-controllers.
  selector: k8s-app == "calico-kube-controllers"
  order: 500
  types:
  - Ingress
  ingress:
  # Deny anything that tries to access the Prometheus port
  # but that doesn't match the necessary selector.
  - action: Deny
    protocol: TCP
    source:
      notSelector: calico-prometheus-access == "true"
    destination:
      ports:
      - 9094
```

> **Note**: The above policy is installed in the calico-system namespace. If your cluster has {{site.prodname}} installed
> in the kube-system namespace, you will need to create the policy in that namespace instead.
{: .alert .alert-info}

Then, use `calicoctl` to apply this policy.

```bash
calicoctl apply -f kube-controllers-prometheus-policy.yaml
```

## Using an allow-list approach

### Overview

The basic process is as follows:

1. Create host endpoints for each node that you'd like to secure.
1. Create a network policy that allows desired traffic to the {{site.prodname}} metrics endpoints.
1. Apply labels to allow access to the Prometheus metrics.

### Example for {{site.nodecontainer}}

1. List the nodes on which {{site.prodname}} is running with the following command.

   ```bash
   calicoctl get nodes
   ```

   In this case, we have two nodes in the cluster.

   ```
   NAME
   kubeadm-master
   kubeadm-node-0
   ```
   {: .no-select-button}

1. Create host endpoints for each {{site.prodname}} node.

   Create a file named `host-endpoints.yaml` containing a host endpoint for each node listed
   above. In this example, the contents would look like this.

   ```yaml
   apiVersion: projectcalico.org/v3
   kind: HostEndpoint
   metadata:
     name: kubeadm-master.eth0
     labels:
       running-calico: "true"
   spec:
     node: kubeadm-master
     interfaceName: eth0
     expectedIPs:
     - 10.100.0.15
   ---
   apiVersion: projectcalico.org/v3
   kind: HostEndpoint
   metadata:
     name: kubeadm-node-0.eth0
     labels:
       running-calico: "true"
   spec:
     node: kubeadm-node-0
     interfaceName: eth0
     expectedIPs:
     - 10.100.0.16
   ```

   In this file, replace `eth0` with the desired interface name on each node, and populate the
   `expectedIPs` section with the IP addresses on that interface.

   Note the use of a label to indicate that this host endpoint is running {{site.prodname}}. The
   label matches the selector of the network policy created in step 1.

   Then, use `calicoctl` to apply the host endpoints with the following command. This will prevent all
   traffic to and from the host endpoints.

   ```bash
   calicoctl apply -f host-endpoints.yaml
   ```

   > **Note**: {{site.prodname}} allows some traffic as a failsafe even after applying this policy. This can
   > be adjusted using the `failsafeInboundHostPorts` and `failsafeOutboundHostPorts` options
   > on the [FelixConfiguration resource](../../reference/resources/felixconfig).
   {: .alert .alert-info}

1. Create a network policy that allows access to the {{site.nodecontainer}} Prometheus metrics port.

   Now let's create a network policy that allows access to the Prometheus metrics port such that
   only endpoints with the label `calico-prometheus-access: true` can access the metrics.

   To do this, create a file named `calico-prometheus-policy.yaml` with the following contents.

   ```yaml
   apiVersion: projectcalico.org/v3
   kind: GlobalNetworkPolicy
   metadata:
     name: restrict-calico-node-prometheus
   spec:
     # Select all {{site.prodname}} nodes.
     selector: running-calico == "true"
     order: 500
     types:
     - Ingress
     ingress:
     # Allow traffic from selected sources to the Prometheus port.
     - action: Allow
       protocol: TCP
       source:
         selector: calico-prometheus-access == "true"
       destination:
         ports:
         - 9091
   ```

   This policy selects all endpoints that have the label `running-calico: true`, and enforces a single ingress deny rule.
   The ingress rule allows traffic to port 9091 from any source with the label `calico-prometheus-access: true`, meaning
   all {{site.prodname}} workload endpoints, host endpoints, and global network sets that have the label will be allowed access.

   Then, use `calicoctl` to apply this policy.

   ```bash
   calicoctl apply -f calico-prometheus-policy.yaml
   ```

1. Apply labels to any endpoints that should have access to the metrics.

   At this point, only endpoints that have the label `calico-prometheus-access: true` can reach
   {{site.prodname}}'s Prometheus metrics endpoints on each node. To grant access, simply add this label to the
   desired endpoints.

   For example, to allow access to a Kubernetes pod you can run the following command.

   ```bash
   kubectl label pod my-prometheus-pod calico-prometheus-access=true
   ```

   If you would like to grant access to a specific IP address in your network, you
   can create a [global network set](../../reference/resources/globalnetworkset) using `calicoctl`.

   For example, creating the following network set would grant access to a host with IP 172.15.0.101.

   ```yaml
   apiVersion: projectcalico.org/v3
   kind: GlobalNetworkSet
   metadata:
     name: calico-prometheus-set
     labels:
       calico-prometheus-access: "true"
   spec:
     nets:
     - 172.15.0.101/32
   ```

### Additional steps for Typha deployments

If your {{site.prodname}} installation uses the Kubernetes API datastore and has greater than 50 nodes, it is likely
that you have installed Typha. This section shows how to use an additional network policy to secure the Typha
Prometheus endpoints.

After following the steps above, create a file named `typha-prometheus-policy.yaml` with the following contents.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: restrict-typha-prometheus
spec:
  # Select all {{site.prodname}} nodes.
  selector: running-calico == "true"
  order: 500
  types:
  - Ingress
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: calico-prometheus-access == "true"
    destination:
      ports:
      - 9093
```

This policy selects all endpoints that have the label `running-calico: true`, and enforces a single ingress deny rule.
The ingress rule allows traffic to port 9093 from any source with the label `calico-prometheus-access: true`, meaning
all {{site.prodname}} workload endpoints, host endpoints, and global network sets that have the label will be allowed access.

Then, use `calicoctl` to apply this policy.

```bash
calicoctl apply -f typha-prometheus-policy.yaml
```

### Example for kube-controllers

If your {{site.prodname}} installation exposes metrics from kube-controllers, you can limit access to those metrics
with the following network policy.

Create a file named `kube-controllers-prometheus-policy.yaml` with the following contents.

```yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: restrict-kube-controllers-prometheus
  namespace: calico-system
spec:
  selector: k8s-app == "calico-kube-controllers"
  order: 500
  types:
  - Ingress
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: calico-prometheus-access == "true"
    destination:
      ports:
      - 9094
```
Then, use `calicoctl` to apply this policy.

```bash
calicoctl apply -f kube-controllers-prometheus-policy.yaml
```
