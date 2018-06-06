---
title: Securing Calico's own communications
---

## About securing {{site.prodname}}'s own communications

By generalizing the approach to [securing {{site.prodname}}'s metrics
endpoints](secure-metrics), {{site.prodname}}'s own communications can be secured by
{{site.prodname}} policy.  This defends against someone attacking the cluster by trying to
impersonate a {{site.prodname}} component; the {{site.prodname}} policy will prevent them
from successfully connecting to real {{site.prodname}} components, and they will not be
able to exfiltrate privileged information, or to modify the cluster's networking or
security.

## Protected servers

We use the term 'protected server' for each {{site.prodname}} service that we want to
protect: {{site.prodname}}'s etcd servers and any other {{site.prodname}} components that
accept incoming connections.  For example, the {{site.nodecontainer}} Prometheus metrics
endpoints.  A protected server runs on certain hosts within the cluster, and serves on a
particular TCP or UDP port.

## Allowing other traffic by default

You need to [decide how to handle traffic that is _not_ to a protected
server](secure-metrics#choosing-an-approach).

If you are [using a port blacklist
approach](secure-metrics#using-a-port-blacklist-approach), configure a default allow
policy like this:

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: bl-default-allow
spec:
  selector: bl-default-allow == "true"
  order: 5000
  ingress:
  - action: Allow
  egress:
  - action: Allow
```

We will add a `bl-default-allow == "true"` label to each HostEndpoint where traffic should
be allowed by default.

## Policy for each protected server

For each protected server `xyz`, configure a policy that only allows access to that server
from clients with the label `allowed-xyz-client`, like this (with `2379` replaced by
the correct port number for that server):

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: protected-xyz-server
spec:
  selector: protected-xyz-server == "true"
  order: 500
  types:
  - Ingress
  ingress:
  - action: Deny
    protocol: TCP
    source:
      notSelector: has(allowed-xyz-client)
    destination:
      ports:
      - 2379
```

When a protected server runs host-networked, as is usually the case for {{site.prodname}}
components, that policy needs to be associated with a HostEndpoint for each possible
interface over which an attempted incoming connection could arrive.  We will put a
`protected-xyz-server == "true"` label on each such HostEndpoint, when we configure it.

If a protected server runs non-host-networked, there should be a `protected-xyz-server ==
"true"` label on the server's WorkloadEndpoint, so that the policy above will apply to
that workload.

## Identifying allowed clients

Each allowed client must have the appropriate `allowed-xyz-client` label (or labels, if it
is an allowed client for multiple servers).  Each `allowed-xyz-client` label eventually
turns into a list of allowed source IP addresses, and, when an attempted incoming
connection reaches a protected server, {{site.prodname}} enforces that that connection's
source IP is one of the allowed ones.

There are three ways that a valid client's IP address can get into that allowed list.

1. If the client is a non-host-networked workload, you should put the `allowed-xyz-client`
   label on its WorkloadEndpoint.  Then the WorkloadEndpoint's IP will be allowed.

2. If the client runs host-networked on a node where {{site.prodname}} is running, you
   should configure a HostEndpoint for the interface over which that client will contact
   the server, with the `allowed-xyz-client` label and with the source IP as one of the
   HostEndpoint's `expectedIPs`.

3. You can create a
   [GlobalNetworkSet](../../reference/calicoctl/resources/globalnetworkset) with the
   `allowed-xyz-client` label and the (additional) source IPs that are allowed to access
   the `xyz` server.

## Configuring HostEndpoints

You can now configure a HostEndpoint on each host where there is a protected
host-networked server or valid client running, and for each interface over which
connections to a protected server could be made.  Each HostEndpoint should look like this:

```yaml
apiVersion: projectcalico.org/v3
kind: HostEndpoint
metadata:
  name: <node_name>-<interface_name>
  labels:
    bl-default-allow: true
    protected-xyz-server: true
    protected-pqr-server: true
    allowed-abc-client: true
    allowed-def-client: true
spec:
  interfaceName: <interface_name>
  node: <node_name>
  expectedIPs:
  - <allowed_client_source_ip>
  - <allowed_client_source_ip>
  - ...
```

with:

-  a `protected-xyz-server` label for each protected server that is running host-networked
   on that node

-  an `allowed-xyz-client` label for each protected server that a host-networked client on
   that node is allowed to access

-  an `<allowed_client_source_ip>` for each source IP that a client connecting from that
   node could use

-  the `bl-default-allow: true` if you are generally allowing traffic through
   HostEndpoints that is _not_ to a protected server.

> **Tip**: If you have a protected server running on a host that is
> not yet {{site.prodname}}-protected, first [set
> up](../../getting-started/bare-metal/installation/container) [host
> protection](../../getting-started/bare-metal/bare-metal) on that
> host.
{: .alert .alert-success}

## Pruning Felix's failsafe ports

{{site.prodname}}'s Felix component is normally configured with a set of failsafe ports
that are always allowed through HostEndpoints, regardless of any policy.  Without these,
it is too easy for a {{site.prodname}} operator to deny an essential communication path
when configuring a HostEndpoint, in a way that cannot be reverted because the reversion
requires the communication path that is now denied.

However, once you have specific policy in place for a protected server (as above), it is
important that that server's port is *no longer configured* as one of Felix's failsafe
ports.  Otherwise the effect of that failsafe port will be to continue to allow connection
from *all* possible clients.

To deconfigure a failsafe port, set the
[FelixConfiguration](../../reference/calicoctl/resources/felixconfig)
`failsafeInboundHostPorts` and `failsafeOutboundHostPorts` fields to their default values
*minus* the port(s) that you are deconfiguring.  For example, to remove the etcd port
(2379), which is normally failsafe:

-  Get and save the existing FelixConfiguration to a file:

   ```shell
   calicoctl get felixconfiguration default -o yaml > fc.yml
   ```

-  Edit the file so that the `failsafeInboundHostPorts` reads like this (or add it if not
   yet there):

   ```shell
     failsafeInboundHostPorts:
     - protocol: TCP
       port: 22
     - protocol: UDP
       port: 68
     - protocol: TCP
       port: 179
     - protocol: TCP
       port: 2380
     - protocol: TCP
       port: 6666
     - protocol: TCP
       port: 6667
   ```

-  Apply the updated configuration:

   ```shell
   calicoctl apply -f fc.yml
   ```
