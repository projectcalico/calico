---
title: Secure BGP sessions
description: Configure BGP passwords to prevent attackers from injecting false routing information.
canonical_url: 'https://docs.tigera.io/master/security/comms/secure-bgp'
---

### Big picture

Use BGP passwords to prevent attackers from injecting false routing information.

### Value

Setting a password on a BGP peering between BGP speakers means that a peering will only
work when both ends of the peering have the same password. This provides a layer of defense
against an attacker impersonating an external BGP peer or a workload in the cluster, for
example in order to inject malicious routing information into the cluster.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **BGPPeer** with password field

### Concepts

#### Password protection on BGP sessions

Password protection is a [standardized](https://tools.ietf.org/html/rfc5925) optional
feature of BGP sessions.  The effect is that the two peers at either end of a BGP session
can only communicate, and exchange routing information, if they are both configured with
the same password.

Please note that password use does not cause the data exchange to be *encrypted*.  It
remains relatively easy to *eavesdrop* on the data exchange, but not to *inject* false
information.

#### Using Kubernetes secrets to store passwords

In Kubernetes, the Secret resource is designed for holding sensitive information,
including passwords.  Therefore, for this {{site.prodname}} feature, we use Secrets to
store BGP passwords.

### How to

To use a password on a BGP peering:

1.  Create (or update) a Kubernetes secret in the namespace where {{site.noderunning}} is
    running, so that it has a key whose value is the desired password.  Note the secret
    name and the key name.

    > **Note:** BGP passwords must be 80 characters or fewer.  If a
    > password longer than that is configured, the BGP sessions with
    > that password will fail to be established.
    {: .alert .alert-info}

1.  Ensure that {{site.noderunning}} has RBAC permissions to access that secret.

1.  Specify the secret and key name on the relevant BGPPeer resource.

#### Create or update Kubernetes secret

For example:

```
kubectl create -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: bgp-secrets
  namespace: calico-system
type: Opaque
stringData:
  rr-password: very-secret
EOF
```

> **Note:** If {{site.noderunning}} in your cluster is running in a namespace other than calico-system,
> you should create the secret in that namespace instead of in calico-system.
{: .alert .alert-info}

To use this password below in a BGPPeer resource, you need to note the secret name
`bgp-secrets` and key name `rr-password`.

#### Ensure RBAC permissions

The {{site.noderunning}} pod must have permission to access that secret.  To allow
{{site.noderunning}} to access that secret, you would configure:

```
kubectl create -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-access
  namespace: calico-system
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["bgp-secrets"]
  verbs: ["watch", "list", "get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secret-access
  namespace: calico-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: secret-access
subjects:
- kind: ServiceAccount
  name: calico-node
  namespace: calico-system
EOF
```

#### Specify secret and key name on the BGP resource

The BGP password can be specified on separate resources depending on the use case.
Specify the password on the BGP peer in order to secure specific BGP peerings or
specify the password in the BGP configuration in order to set the password for all
intra cluster communications in a node to node mesh.

{% tabs %}
  <label:Specific or external peerings,active:true>
<%

When [configuring a BGP peer]({{site.baseurl}}/networking/bgp),
include the secret and key name in the specification of the BGPPeer resource, like this:

```
apiVersion: projectcalico.org/v3
kind: BGPPeer
metadata:
  name: bgppeer-global-3040
spec:
  peerIP: 192.20.30.40
  asNumber: 64567
  password:
    secretKeyRef:
      name: bgp-secrets
      key: rr-password
```

%>

  <label:Node to node mesh,active:true>
<%

Include the secret in the default [BGP configuration]({{site.baseurl}}/reference/resources/bgpconfig)
similar to the following:

```
kind: BGPConfiguration
apiVersion: projectcalico.org/v3
metadata:
  name: default
spec:
  logSeverityScreen: Info
  nodeToNodeMeshEnabled: true
  nodeMeshPassword:
    secretKeyRef:
      name: bgp-secrets
      key: rr-password
```
> **Note**: Node to node mesh must be enabled in order to set node to node mesh
> BGP password.
{: .alert .alert-info}

%>

{% endtabs %}

### Above and beyond

For more detail about the BGPPeer resource, see
[BGPPeer]({{site.baseurl}}/reference/resources/bgppeer).

For more on configuring BGP peers, see [configuring BGP
peers]({{site.baseurl}}/networking/bgp).
