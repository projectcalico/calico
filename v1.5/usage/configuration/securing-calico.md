---
title: Securing Calico
sitemap: false 
---

What Calico does and does not provide
=====================================

Currently, Calico implements security policy that ensures that:

-   a workload endpoint cannot spoof its source address
-   all traffic going to an endpoint must be accepted by the inbound
    policy attached to that endpoint
-   all traffic leaving an endpoint must be accepted by the outbound
    policy attached to that endpoint.

However, there are several areas that Calico does not currently cover
(we're working on these and we'd love to hear from you if you're
interested!). Calico does not:

-   prevent an endpoint from probing the network (if its outbound policy
    allows it); in particular, it doesn't prevent an endpoint from
    contacting compute hosts or etcd
-   prevent an endpoint from flooding its host with DNS/DHCP/ICMP
    traffic
-   prevent a compromised host from spoofing packets.

Since the outbound policy is typically controlled by the application
developer who owns the endpoint (at least when Calico is used with
OpenStack), it's a management challenge to use that to enforce *network*
policy.

How Calico uses iptables
========================

Calico needs to add its security policy rules to the "INPUT", "OUTPUT"
and "FORWARD" chains of the iptables "filter" table. To minimise the
impact on the top-level chains, Calico inserts a single rule at the
start of each of the kernel chains, which jumps to Calico's own chain.

The INPUT chain is traversed by packets which are destined for the host
itself. Calico applies workloads' outbound policy in the input chain as
well as the policy for host endpoints.

For workload traffic hitting the INPUT chain, Calico whitelists some
essential bootstrapping traffic, such as DHCP, DNS and the OpenStack
metadata traffic. Other traffic from local workload endpoints passes
through the outbound rules for the endpoint. Then, it hits a
configurable rule that either drops the traffic or allows it to continue
to the remainder of the INPUT chain.

Presently, the Calico FORWARD chain is not similarly configurable. All
traffic that is heading to or from a local endpoint is processed through
the relevant security policy. Then, if the policy accepts the traffic,
it is accepted. If the policy rejects the traffic it is immediately
dropped.

Calico installs host endpoint outbound rules in the OUTPUT chain.

To prevent IPv6-enabled endpoints from spoofing their IP addresses,
Felix inserts a reverse path filtering rule in the iptables "raw"
PREROUTING chain. (For IPv4, it enables the rp\_filter sysctl on each
interface that it controls.)

Securing iptables
=================

In a production environment, we recommend setting the default policy for
the INPUT and FORWARD chains to be DROP and then explicitly whitelisting
the traffic that should be allowed.

Securing etcd
=============

Limiting network access to etcd
-------------------------------

Calico uses etcd to store and forward the configuration of the network
from plugin to the Felix agent. By default, etcd is writable by anyone
with access to its REST interface. We plan to use the RBAC feature of an
upcoming etcd release to improve this dramatically. However, until that
work is done, we recommend blocking access to etcd from all but the IP
range(s) used by the compute nodes and plugin.

Calico's host endpoint support (see [this document]({{site.baseurl}}/{{page.version}}/getting-started/bare-metal/bare-metal)) can be used to
enforce such policy.

Using TLS to encrypt and authenticate communication with etcd
-------------------------------------------------------------

Calico supports etcd's TLS-based security model, which supports the
encryption (and authentication) of traffic between Calico components and
the etcd cluster.

> **WARNING**
>
> Calico's TLS support uses the Python urllib3 library.
> Unfortunately, we've seen issues with TLS in some of the common
> versions of urllib3 including the version that ships with Ubuntu
> 14.04 (1.7.1) and versions 1.11-1.12. Version 1.13 appears to
> work well.
>
> In addition, no versions of urllib3 support using IP addresses in the
> `subjectAltName` field of a TLS certificate. An IP address can still
> be used in the common name (CN) field but this restriction prevents
> the creation of a certificate that contains multiple IP addresses.
> urllib3 does support domain name-based `subjectAltNames`, allowing for
> multiple domain names to be embedded in the certificate.
>
> For more details of the restrictions, see [this GitHub > issue](https://github.com/projectcalico/felix/issues/933).

To enable TLS support:

-   Follow the instructions in the [etcd security
    guide](https://coreos.com/etcd/docs/latest/security.html) to create
    a certificate authority and enable TLS in etcd. We recommend
    enabling both client and peer authentication. This will enable
    security between Calico and etcd as well as between different nodes
    in the etcd cluster.

    > **NOTE**
    >
    > etcd proxies communicate with the cluster as peers so they need to
    > have peer certificates.
    >

-   Issue a private key and client certificate for each
    Calico component. In OpenStack, you'll need one certificate for each
    control node and one for each compute node.

-   If using OpenStack, configure each Neutron control node to use TLS:
    -   Put the PEM-encoded private key and certificates in a secure
        place that is only accessible by the user that Neutron will
        run as.

        > **NOTE**
        >
        > Each control node should have its own private key and
        > certificate. The certificate encodes the IP address or
        > hostname of the owner.
        >

    -   Modify `/etc/neutron/plugins/ml2_conf.ini` to include a
        `[calico]` section that tells it where to find the key and
        certificates:

            [calico]
            etcd_key_file=<location of PEM-encoded private key>
            etcd_cert_file=<location of PEM-encoded client certificate>
            etcd_ca_cert_file=<location of PEM-encoded CA certificate>

        > **NOTE**
        >
        > Calico will validate the etcd server's certificate against the
        > `etcd_host` configuration parameter. `etcd_host` defaults
        >  to "localhost". Issuing a certificate for "localhost"
        >  doesn't tie the certificate to any particular server.
        >  Therefore, even if you're connecting to the local server,
        >  you may wish to issue the certificate for the server's
        >  domain name and configure `etcd_host` to match.
        >

    -   Restart neutron-server.

-   Unless your Calico system uses `calicoctl node` to install and
    configure Felix, configure each Felix with its own key and
    certificate:

    > **NOTE**
    >
    > In systems that use `calicoctl node` (such as Docker, Kubernetes
    > and other container orchestrators), you should use the
    > `calicoctl` tool to configure TLS. See the [Etcd Secure
    >  Cluster]({{site.baseurl}}/{{page.version}}/reference/advanced/etcd-secure)
    >  document for details.
    >

    -   Generate a certificate and key pair for each Felix.
    -   Put the PEM-encoded private key and certificates in a secure
        place that is only accessible by the root user. For example,
        create a directory `/etc/calico/secure`:

            $ mkdir -p /etc/calico/secure
            $ chown -R root:root /etc/calico/secure
            $ chmod 0700 /etc/calico/secure

        > **NOTE**
        >
        > Each Felix-controlled node should have its own private key and
        > certificate. The certificate encodes the IP address or
        > hostname of the owner.
        >

    -   Modify Felix's configuration file `/etc/calico/felix.cfg` to
        tell it where to find the key and certificates:

            [global]
            EtcdScheme = https
            EtcdKeyFile = <location of PEM-encoded private key>
            EtcdCertFile = <location of PEM-encoded client certificate>
            EtcdCaFile = <location of PEM-encoded CA certificate>
            ...

        > **NOTE**
        >
        > Calico will validate the etcd server's certificate against the
        > host part of the `EtcdAddr` configuration parameter.
        > `EtcdAddr` defaults to "localhost:4001". Issuing a
        > certificate for "localhost" doesn't tie the certificate to
        > any particular server. Therefore, even if you're
        > connecting to the local server, you may wish to issue the
        > certificate for the server's domain name and configure
        > `EtcdAddr` to match.
        >

    -   Restart Felix.

Host endpoint failsafe rules
============================

By default for host endpoints (in order to avoid breaking all
connectivity to a host) Calico whitelists ssh to and etcd traffic from
the host running Felix. The filter rules are based entirely on ports so
they are fairly broad.

This behaviour can be configured or disabled via configuration
parameters; see [here]({{site.baseurl}}/{{page.version}}/usage/configuration).
