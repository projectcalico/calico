## Node requirements

- AMD64 processor

- Linux kernel 3.10 or later with [required dependencies](#kernel-dependencies). 
  The following distributions have the required kernel, its dependencies, and are 
  known to work well with {{site.prodname}} and {{include.orch}}.
  - RedHat Linux 7{% if include.orch == "Kubernetes" or include.orch == "host protection" %}
  - CentOS 7
  - CoreOS Container Linux stable
  - Ubuntu 16.04
  - Debian 8
  {% endif %}{% if include.orch == "OpenShift" %}
  - CentOS 7
  {% endif %}{% if include.orch == "OpenStack" %}
  - Ubuntu 16.04
  - CentOS 7
  {% endif %}

## Key/value store

{{site.prodname}} {{page.version}} requires a key/value store accessible by all 
{{site.prodname}} components. {% if include.orch == "Kubernetes" %} On Kubernetes,
you can configure {{site.prodname}} to access an etcdv3 cluster directly or to
use the Kubernetes API datastore.{% endif %}{% if include.orch == "OpenShift" %} On
OpenShift, {{site.prodname}} can share an etcdv3 cluster with OpenShift, or
you can set up an etcdv3 cluster dedicated to {{site.prodname}}.{% endif %}
{% if include.orch == "OpenStack" %}If you don't already have an etcdv3 cluster
to connect to, we provide instructions in the [installation documentation](./installation/).{% endif %}

## Network requirements

{{site.prodname}} requires the network to allow the following types of traffic.

| Traffic | Protocol | Port |
| ------- | -------- | ---- |
| BGP     | TCP      | 179  |
| IPIP\*  | 4        | n/a  |

\* Our manifests enable IPIP by default. If you disable IPIP, you won't need to
   allow IPIP traffic. Refer to [Configuring IP-in-IP](../../usage/configuration/ip-in-ip) for more information.

> **Tip**: On GCE, you can allow this traffic using firewall rules. In AWS, use 
> EC2 security group rules.
{: .alert .alert-success}
