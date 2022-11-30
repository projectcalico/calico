## Node requirements

- x86-64, arm64, ppc64le, or s390x processor

- Linux kernel 3.10 or later with [required dependencies](#kernel-dependencies).
  The following distributions have the required kernel, its dependencies, and are
  known to work well with {{site.prodname}} and {{include.orch}}.
  - RedHat Linux 7{% if include.orch == "Kubernetes" or include.orch == "host protection" %}
  - CentOS 7
  - CoreOS Container Linux stable
  - Ubuntu 16.04
  - Debian 8
  {% endif %}{% if include.orch == "OpenShift" %}
  - RedHat Container OS
  {% endif %}{% if include.orch == "OpenStack" %}
  - Ubuntu 18.04
  - CentOS 8
  {% endif %}

- {{site.prodname}} must be able to manage `cali*` interfaces on the host. When IPIP is
  enabled (the default), {{site.prodname}} also needs to be able to manage `tunl*` interfaces.
  When VXLAN is enabled, {{site.prodname}} also needs to be able to manage the `vxlan.calico` interface.

  > **Note**: Many Linux distributions, such as most of the above, include NetworkManager.
  > By default, NetworkManager does not allow {{site.prodname}} to manage interfaces.
  > If your nodes have NetworkManager, complete the steps in
  > [Preventing NetworkManager from controlling {{site.prodname}} interfaces]({{ site.baseurl }}/maintenance/troubleshoot/troubleshooting#configure-networkmanager)
  > before installing {{site.prodname}}.
  {: .alert .alert-info}
  
- If your Linux distribution comes with installed Firewalld or another iptables manager it should be disabled. 
  These may interfere with rules added by {{site.prodname}} and result in unexpected behavior.
  
  > **Note**: 
  > If a host firewall is needed, it can be configured by {{site.prodname}} HostEndpoint and GlobalNetworkPolicy.
  > More information about configuration at [Security for host]({{ site.baseurl }}/security/hosts).
  {: .alert .alert-info}

## Key/value store

{{site.prodname}} {{page.version}} requires a key/value store accessible by all
{{site.prodname}} components.
{%- if include.orch == "OpenShift" %}
With OpenShift, the Kubernetes API datastore is used for the key/value store.{% endif -%}
{%- if include.orch == "Kubernetes" %}
On Kubernetes, you can configure {{site.prodname}} to access an etcdv3 cluster directly or to
use the Kubernetes API datastore.{% endif -%}
{%- if include.orch == "OpenStack" %}
For production you will likely want multiple
nodes for greater performance and reliability.  If you don't already have an
etcdv3 cluster to connect to, please refer to {% include open-new-window.html text='the upstream etcd
docs' url='https://coreos.com/etcd/' %} for detailed advice and setup.{% endif %}{% if include.orch == "host protection" %}The key/value store must be etcdv3.{% endif %}

## Network requirements

Ensure that your hosts and firewalls allow the necessary traffic based on your configuration.

| Configuration                                                | Host(s)              | Connection type | Port/protocol |
|--------------------------------------------------------------|----------------------|-----------------|---------------|
| {{site.prodname}} networking (BGP)                           | All                  | Bidirectional   | TCP 179 |
| {{site.prodname}} networking with IP-in-IP enabled (default) | All                  | Bidirectional   | IP-in-IP, often represented by its protocol number `4` |
{%- if include.orch == "OpenShift" %}
| {{site.prodname}} networking with VXLAN enabled              | All                  | Bidirectional   | UDP 4789 |
| Typha access                                                 | Typha agent hosts    | Incoming        | TCP 5473 (default) |
| All                                                          | kube-apiserver host  | Incoming        | Often TCP 443 or 8443\* |
{%- elsif include.orch == "Kubernetes" %}
| {{site.prodname}} networking with VXLAN enabled              | All                  | Bidirectional   | UDP 4789 |
| {{site.prodname}} networking with Typha enabled              | Typha agent hosts    | Incoming        | TCP 5473 (default) |
| {{site.prodname}} networking with IPv4 Wireguard enabled     | All                  | Bidirectional   | UDP 51820 (default) |
| {{site.prodname}} networking with IPv6 Wireguard enabled     | All                  | Bidirectional   | UDP 51821 (default) |
| flannel networking (VXLAN)                                   | All                  | Bidirectional   | UDP 4789 |
| All                                                          | kube-apiserver host  | Incoming        | Often TCP 443 or 6443\* |
| etcd datastore                                               | etcd hosts           | Incoming        | {% include open-new-window.html text='Officially' url='http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt' %}  TCP 2379 but can vary |
{%- else %}
| All                                                          | etcd hosts           | Incoming        | {% include open-new-window.html text='Officially' url='http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.txt' %}  TCP 2379 but can vary |
{%- endif %}
{%- if include.orch == "Kubernetes" or include.orch == "OpenShift" %}

\* _The value passed to kube-apiserver using the `--secure-port` flag. If you cannot locate this, check the `targetPort` value returned by `kubectl get svc kubernetes -o yaml`._
{% endif -%}
{%- if include.orch == "OpenStack" %}

\* _If your compute hosts connect directly and don't use IP-in-IP, you don't need to allow IP-in-IP traffic._
{%- endif %}

## Privileges

Ensure that {{site.prodname}} has the `CAP_SYS_ADMIN` privilege.

The simplest way to provide the necessary privilege is to run {{site.prodname}} as root or in a privileged container.

{%- if include.orch == "Kubernetes" %}
When installed as a Kubernetes daemon set, {{site.prodname}} meets this requirement by running as a
privileged container. This requires that the kubelet be allowed to run privileged
containers. There are two ways this can be achieved.

- Specify `--allow-privileged` on the kubelet (deprecated).
- Use a {% include open-new-window.html text='pod security policy' url='https://kubernetes.io/docs/concepts/policy/pod-security-policy/' %}.
{% endif -%}
