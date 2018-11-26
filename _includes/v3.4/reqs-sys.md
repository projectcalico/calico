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
to connect to, we provide instructions in the [installation documentation](./installation/).{% endif %}{% if include.orch == "host protection" %}The key/value store must be etcdv3.{% endif %}

## Network requirements

Ensure that your hosts and firewalls allow the necessary traffic based on your configuration.

| Configuration                                                | Host(s)              | Connection type | Port/protocol |
|--------------------------------------------------------------|----------------------|-----------------|---------------|
| {{site.prodname}} networking (BGP)                           | All                  | Bidirectional   | TCP 179 |
| {{site.prodname}} networking with IP-in-IP enabled (default) | All                  | Bidirectional   | IP-in-IP, often represented by its protocol number `4` |
{%- if include.orch == "Kubernetes" %}
| {{site.prodname}} networking with Typha enabled              | Typha agent hosts    | Incoming        | TCP 5473 (default) |
| flannel networking (VXLAN)                                   | All                  | Bidirectional   | UDP 4789 |
| All                                                          | kube-apiserver host  | Incoming        | Often TCP 443 or 6443\* |
| etcd datastore                                               | etcd hosts           | Incoming        | [Officially](http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt) TCP 2379 but can vary |
{%- else %}
| All                                                          | etcd hosts           | Incoming        | [Officially](http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt) TCP 2379 but can vary |
{%- endif %}
{%- if include.orch == "OpenShift" %}
| All                                                          | kube-apiserver host  | Incoming        | Often TCP 443 or 8443\* |
{%- endif %}
{%- if include.orch == "Kubernetes" or include.orch == "OpenShift" %}

\* _The value passed to kube-apiserver using the `--secure-port` flag. If you cannot locate this, check the `targetPort` value returned by `kubectl get svc kubernetes -o yaml`._
{% endif -%}
{%- if include.orch == "OpenStack" %}

\* _If your compute hosts connect directly and don't use IP-in-IP, you don't need to allow IP-in-IP traffic._
{% endif -%}

## Privileges

Ensure that {{site.prodname}} has the `CAP_SYS_ADMIN` privilege.

The simplest way to provide the necessary privilege is to run {{site.prodname}} as root or in a privileged container.

{%- if include.orch == "Kubernetes" %}
When installed as a Kubernetes daemon set, {{site.prodname}} meets this requirement by running as a
privileged container. This requires that the kubelet be allowed to run privileged
containers. There are two ways this can be achieved.

- Specify `--allow-privileged` on the kubelet (deprecated).
- Use a [pod security policy](https://kubernetes.io/docs/concepts/policy/pod-security-policy/).
{% endif -%}
