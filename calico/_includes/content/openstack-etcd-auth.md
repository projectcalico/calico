
## Configuration for etcd authentication

If your etcd cluster has authentication enabled, you must also configure the
relevant {{site.prodname}} components with an etcd user name and password.  You
can create a single etcd user for {{site.prodname}} that has permission to read
and write any key beginning with `/calico/`, or you can create specific etcd
users for each component, with more precise permissions.

This table sets out where to configure each component of {{site.prodname}} for
OpenStack, and the detailed access permissions that each component needs:

| Component      | Configuration                                                                                                  | Access |
|----------------|----------------------------------------------------------------------------------------------------------------|--------|
| Felix          | `CALICO_ETCD_USERNAME` and `CALICO_ETCD_PASSWORD` variables in Felix's environment on each compute node.       | [See here]({{ site.baseurl }}/reference/etcd-rbac/calico-etcdv3-paths#felix-as-a-stand-alone-process) |
| Neutron driver | `etcd_username` and `etcd_password` in `[calico]` section of `/etc/neutron/neutron.conf` on each control node. | [See here]({{ site.baseurl }}/reference/etcd-rbac/calico-etcdv3-paths#openstack-calico-driver-for-neutron) |
| DHCP agent     | `etcd_username` and `etcd_password` in `[calico]` section of `/etc/neutron/neutron.conf` on each compute node. | [See here]({{ site.baseurl }}/reference/etcd-rbac/calico-etcdv3-paths#openstack-calico-dhcp-agent) |
