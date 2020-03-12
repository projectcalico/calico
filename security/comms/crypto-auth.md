---
title: Configure encryption and authentication
description: Enable TLS authentication and encryption for various Calico components.
canonical_url: '/security/comms/crypto-auth'
---

## Connections from {{site.prodname}} components to etcd

If you are using the etcd datastore, we recommend enabling mutual TLS authentication on
its connections as follows.

- [Configure etcd](https://coreos.com/etcd/docs/latest/op-guide/security.html) to encrypt its
  communications with TLS and require clients to present certificates signed by the etcd certificate
  authority.

- Configure each {{site.prodname}} component to verify the etcd server's identity and to present
  a certificate to the etcd server that is signed by the etcd certificate authority.
  - [{{site.nodecontainer}}](../../reference/node/configuration)
  - [`calicoctl`](../../getting-started/calicoctl/configure/etcd)
  - [CNI plugin](../../reference/cni-plugin/configuration#etcd-location) (Kubernetes and OpenShift only)
  - [Kubernetes controllers](../../reference/kube-controllers/configuration#configuring-datastore-access) (Kubernetes and OpenShift only)
  - [Felix](../../reference/felix/configuration#etcd-datastore-configuration)
  - [Typha](../../reference/typha/configuration#etcd-datastore-configuration) (often deployed in
    larger Kubernetes deployments)
  - [Neutron plugin or ML2 driver](../../networking/openstack/configuration#neutron-server-etcneutronneutronconf) (OpenStack only)
  - [DHCP agent](../../networking/openstack/configuration#neutron-server-etcneutronneutronconf) (OpenStack only)

### Connections from {{site.prodname}} components to kube-apiserver (Kubernetes and OpenShift)

We recommend enabling TLS on kube-apiserver, as well as the client certificate and JSON web token (JWT)
authentication modules. This ensures that all of its communications with {{site.prodname}} components occur
over TLS. The {{site.prodname}} components present either an X.509 certificate or a JWT to kube-apiserver
so that kube-apiserver can verify their identities.

### Connections from Node to Typha (Kubernetes)

We recommend enabling mutual TLS authentication on connections from Node to Typha.
To do so, you must provision Typha with a server certificate with extended key usage `ServerAuth` and Node with a client
certificate with extended key usage `ClientAuth`. Each service will need the private key associated with their certificate.
In addition, you must configure one of the following.

- **SPIFFE identifiers** (recommended): Generate a [SPIFFE](https://github.com/spiffe/spiffe) identifier for Node,
  and include Node's SPIFFE ID in the `URI SAN` field of its certificate.
  Similarly, generate a [SPIFFE](https://github.com/spiffe/spiffe) identifier for Typha,
  and include Typha's SPIFFE ID in the `URI SAN` field of its certificate.

- **Common Name identifiers**: Set a common name on the Typha certificate and a different
  common name on the Node certificate.

> **Tip**: If you are migrating from Common Name to SPIFFE identifiers, you can set both values.
> If either matches, the communication succeeds.
{: .alert .alert-success}

#### Configure Node to Typha TLS based on your deployment

##### Operator deployment

For clusters installed using operator, see how to [provide TLS certificates for Typha and Node](typha-node-tls).

##### Manual/Helm deployment

Here is an example of how you can secure the Node-Typha communications in your
cluster:

1.  Choose a certificate authority, or set up your own.

1.  Obtain or generate the following leaf certificates, signed by that
    authority, and corresponding keys:

    -  A certificate for each Node with Common Name `typha-client` and
       extended key usage `ClientAuth`.

    -  A certificate for each Typha with Common Name `typha-server` and
       extended key usage `ServerAuth`.

1.  Configure each Typha with:

    -  `CAFile` pointing to the certificate authority certificate

    -  `ServerCertFile` pointing to that Typha's certificate

    -  `ServerKeyFile` pointing to that Typha's key

    -  `ClientCN` set to `typha-client`

    -  `ClientURISAN` unset.

1.  Configure each Node with:

    -  `TyphaCAFile` pointing to the Certificate Authority certificate

    -  `TyphaCertFile` pointing to that Node's certificate

    -  `TyphaKeyFile` pointing to that Node's key

    -  `TyphaCN` set to `typha-server`

    -  `TyphaURISAN` unset.

For a [SPIFFE](https://github.com/spiffe/spiffe)-compliant deployment you can
follow the same procedure as above, except:

1.  Choose [SPIFFE
    Identities](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md#2-spiffe-identity)
    to represent Node and Typha.

1.  When generating leaf certificates for Node and Typha, put the relevant
    SPIFFE Identity in the certificate as a URI SAN.

1.  Leave `ClientCN` and `TyphaCN` unset.

1.  Set Typha's `ClientURISAN` parameter to the SPIFFE Identity for Node that
    you use in each Node certificate.

1.  Set Node's `TyphaURISAN` parameter to the SPIFFE Identity for Typha.

For detailed reference information on these parameters, refer to:

- **Typha**: [Node-Typha TLS configuration](../../reference/typha/configuration#felix-typha-tls-configuration)

- **Felix**: [Node-Typha TLS configuration](../../reference/felix/configuration#felix-typha-tls-configuration)
