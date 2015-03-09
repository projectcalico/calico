Calico Security Configuration Model
===================================

.. warning:: The current security configuration model in Calico is based
             primarily on what OpenStack allows users to configure. This is
             shortly being replaced by a new, more flexible model, so this
             article is only for reference of the current setup.

At present, the flow of security information proceeds as follows::

    [Configuration in OpenStack or other orchestrator] -(Plugin)-> [Calico network API] -(ACL Manager)-> [Calico ACL API] -(Felix)-> [Programmed IPTables rules]

When a security group is configured, the Calico orchestrator plugin discovers
the new configuration. This configuration is programmed over the Calico Network
API to the ACL manager. This component transforms the ACLs if necessary and
then programs them over the Calico ACL API to the relevant Felix agent. That
Felix agent then transforms the rules finally into ``iptables`` and ``ipsets``
commands.

Configuration Model: OpenStack
------------------------------

Security in OpenStack is controlled by 3 objects: networks, routers and
security groups.

Groups
~~~~~~

A security group is a collection of rules that may be applied to Neutron ports.
The default action to perform on a packet (both in and outbound) is always
DENY. In addition to the default rule, the user configures exceptions that
allow traffic. These exceptioins carry the following information::

    allow IPv4|IPv6 [<protocol> [<port range>]] traffic from/to <cidr>|<group>

By default 0.0.0.0/0 and ::/0 egress rules are created in every security group,
allowing outbound traffic to all destinations. In the Neutron 'default'
security group, IPv4 and IPv6 rules are auto-created that allow ingress from
VMs in the 'default' security group.

Ports can be added to multiple groups, in which case they receive all rules
from each group they're in. A VM may have multiple ports with different
security group configuration.

Networks and Routers
~~~~~~~~~~~~~~~~~~~~

As discussed in :ref:`opens-external-conn`, networks and routers are not used
in Calico for connectivity purposes. Similarly, they also serve no security
purpose in a Calico environment.

Calico can provide equivalent functionality to networks and routers using
security groups. To achieve it, rather than placing all ports that need to
communicate into a single network, place them all in a security group that
allows ingress from and egress to the same security group.
