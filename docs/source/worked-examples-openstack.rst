.. # Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
   #
   #    Licensed under the Apache License, Version 2.0 (the "License"); you may
   #    not use this file except in compliance with the License. You may obtain
   #    a copy of the License at
   #
   #         http://www.apache.org/licenses/LICENSE-2.0
   #
   #    Unless required by applicable law or agreed to in writing, software
   #    distributed under the License is distributed on an "AS IS" BASIS,
   #    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
   #    implied. See the License for the specific language governing
   #    permissions and limitations under the License.

Worked Examples: Using Calico-based OpenStack
=============================================

Once you've installed OpenStack (see :doc:`openstack`) and configured its
networking (see :doc:`opens-external-conn`) you'll want to let your users start
playing with your brand new cloud.

Before you do, it will be helpful to have a few worked examples for common
deployment scenarios. In particular, this will make it easy for you to set up
topologies and examine their connectivity to try to get an understanding of the
way Calico networks behave.

Example 1: Development Machine
------------------------------

In this example, a user wants to spin up a machine to use as a Linux
development environment. This user has a straightforward use-case: they want a
GUI and SSH access, but relatively little else.

This user is provisioned with a single OpenStack user and single OpenStack
tenant. Neutron will automatically provision them with a single security group,
``default``, that contains the following rules:

- allow all inbound traffic from machines in the ``default`` security group
- allow all outbound traffic to anywhere

Per the instructions in :doc:`opens-external-conn`, this user cannot create
Neutron networks or subnets, but they do have access to the networks created
by the administrator: ``external`` and ``internal``.

Because the user wants to be able to reach the machine from their own laptop,
they need the machine to be reachable from outside the data center. In
vanilla Neutron, this would mean provisioning it with a floating IP, but in
Calico they instead want to make sure the VM is attached to the ``external``
network. To add themselves to this network, the user needs to find out the UUID
for it:

.. code-block:: bash

    $ neutron net-list
    +--------------------------------------+----------+----------------------------------------------------------+
    | id                                   | name     | subnets                                                  |
    +--------------------------------------+----------+----------------------------------------------------------+
    | 8d5dec25-a6aa-4e18-8706-a51637a428c2 | external | 54db559c-5e1d-4bdc-83b0-c479ef2a0ead 172.18.208.0/24     |
    |                                      |          | cf6ceea0-dde0-4018-ab9a-f8f68935622b 2001:db8:a41:2::/64 |
    | fa52b704-7b3c-4c83-8698-244807352711 | internal | 301b3e63-5324-4d62-8e22-ed8dddd50689 10.65.0.0/16        |
    |                                      |          | bf94ccb1-c57c-4c9a-a873-c20cbfa4ecaf 2001:db8:a41:3::/64 |
    +--------------------------------------+----------+----------------------------------------------------------+

As the user can see, the ``external`` network has the UUID
``8d5dec25-a6aa-4e18-8706-a51637a428c2``. Thus, they create the machine with
the following nova boot command:

.. code-block:: bash

    $ nova boot --flavor m1.medium                                  \
                --image debian-wheezy-amd64                         \
                --security-groups default                           \
                --nic "netid=8d5dec25-a6aa-4e18-8706-a51637a428c2"  \
                development-server

This places the VM with a single NIC in the ``external`` network. The VM starts
to boot, and Neutron allocates it an IP address in the ``external`` network:
in this case, both an IPv4 and IPv6 address, as you can see below::

    +--------------------------------------+-----------------------------------------------------------+
    | Property                             | Value                                                     |
    +--------------------------------------+-----------------------------------------------------------+
    | external network                     | 2001:db8:a41:2::1c, 172.18.208.85                         |
    | flavor                               | m1.medium (3)                                             |
    | hostId                               | b80247c27400fc9048ca569c8635f00801654bf676a00d8f08887215  |
    | id                                   | e36f4e62-0efa-4188-87b8-8c96dc6e6028                      |
    | name                                 | development-server                                        |
    | security_groups                      | default                                                   |
    +--------------------------------------+-----------------------------------------------------------+

While the machine boots, this tenant decides to configure their security group.
It needs four extra rules: one for SSH and three for VNC. This developer's
personal machine has the IPv4 address 191.64.52.12, and that's the only machine
they'd like to be able to access their machine. For that reason, they add the
four security group rules:

.. code-block:: bash

    $ neutron security-group-rule-create --protocol tcp                      \
                                         --port-range-min 22                 \
                                         --port-range-max 22                 \
                                         --direction ingress                 \
                                         --remote-ip-prefix 191.64.52.12/32  \
                                         --ethertype IPv4                    \
                                         default

    $ neutron security-group-rule-create --protocol tcp                      \
                                         --port-range-min 5800               \
                                         --port-range-max 5801               \
                                         --direction ingress                 \
                                         --remote-ip-prefix 191.64.52.12/32  \
                                         --ethertype IPv4                    \
                                         default

    $ neutron security-group-rule-create --protocol tcp                      \
                                         --port-range-min 5900               \
                                         --port-range-max 5901               \
                                         --direction ingress                 \
                                         --remote-ip-prefix 191.64.52.12/32  \
                                         --ethertype IPv4                    \
                                         default

    $ neutron security-group-rule-create --protocol tcp                      \
                                         --port-range-min 6000               \
                                         --port-range-max 6001               \
                                         --direction ingress                 \
                                         --remote-ip-prefix 191.64.52.12/32  \
                                         --ethertype IPv4                    \
                                         default

At this stage, the developer's machine is up and running. It can be reached on
its public IP (172.18.208.85), and the developer confirms this by SSHing into
their box. They're now ready to go.
