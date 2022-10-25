---
title: Service IPs
description: Use a floating or fixed IP for a Calico-networked VM.
canonical_url: '/networking/openstack/service-ips'
---

{{site.prodname}} supports two approaches for assigning a service IP to a
{{site.prodname}}-networked VM:

- using a floating IP

- using an additional fixed IP on the relevant Neutron port.

Both of these are standard Neutron practice - in other words, operations that
have long been supported on the Neutron API.  They are not {{site.prodname}}-specific,
except insofar as the {{site.prodname}} driver needs to implement some of the low-level
operations that are needed to make the expected semantics work.

The key semantic difference between those approaches is that:

- With a floating IP, the target VM itself is not aware of the service IP.
  Instead, data sent to the floating IP is DNAT'd, to the target VM's fixed IP,
  before that data reaches the target VM.  So the target VM only ever sees data
  addressed to its fixed IP.

- With the service IP as an additional fixed IP, the target VM is (and must be)
  aware of the service IP, because data addressed to the service IP reaches the
  target VM without any DNAT.

The use of floating IPs is already well known, so we won't labour how to use
those here.  For some additional information on how {{site.prodname}} supports floating
IPs, see [Floating IPs](floating-ips).

The use and maintenance of additional fixed IPs, however, is not so well
known, so in the following transcripts we demonstrate this approach for
assigning a service IP to a {{site.prodname}}-networked VM.

We begin by creating a test VM that will be the target of the service IP.

## Creating a test VM

1. Check the name of the available CirrOS image.

   ```bash
   nova image-list
   ```
   It should return a list of the images and their names.

   ```
   WARNING: Command image-list is deprecated and will be removed after Nova 15.0.0 is released. Use python-glanceclient or openstackclient instead.
   +--------------------------------------+---------------------+--------+--------+
   | ID                                   | Name                | Status | Server |
   +--------------------------------------+---------------------+--------+--------+
   | b69ab3bd-2bbc-4086-b4ae-f01d9f6b5078 | cirros-0.3.2-x86_64 | ACTIVE |        |
   | 866879b9-532b-44c6-a547-ac59de68df2d | ipv6_enabled_image  | ACTIVE |        |
   +--------------------------------------+---------------------+--------+--------+
   ```
   {: .no-select-button}

1. Boot a VM.

   ```bash
   nova boot --flavor m1.tiny --image cirros-0.3.2-x86_64 --nic net-name=demo-net testvm1
   ```

   The response should look similar to the following.

   ```
   +--------------------------------------+------------------------------------------------------------+
   | Property                             | Value                                                      |
   +--------------------------------------+------------------------------------------------------------+
   | OS-DCF:diskConfig                    | MANUAL                                                     |
   | OS-EXT-AZ:availability_zone          | nova                                                       |
   | OS-EXT-SRV-ATTR:host                 | -                                                          |
   | OS-EXT-SRV-ATTR:hypervisor_hostname  | -                                                          |
   | OS-EXT-SRV-ATTR:instance_name        | instance-0000000d                                          |
   | OS-EXT-STS:power_state               | 0                                                          |
   | OS-EXT-STS:task_state                | scheduling                                                 |
   | OS-EXT-STS:vm_state                  | building                                                   |
   | OS-SRV-USG:launched_at               | -                                                          |
   | OS-SRV-USG:terminated_at             | -                                                          |
   | accessIPv4                           |                                                            |
   | accessIPv6                           |                                                            |
   | adminPass                            | HKLzcUT5L52B                                               |
   | config_drive                         |                                                            |
   | created                              | 2017-01-13T13:50:32Z                                       |
   | flavor                               | m1.tiny (1)                                                |
   | hostId                               |                                                            |
   | id                                   | b6d8a3c4-9674-4972-9151-11107b60d622                       |
   | image                                | cirros-0.3.2-x86_64 (b69ab3bd-2bbc-4086-b4ae-f01d9f6b5078) |
   | key_name                             | -                                                          |
   | metadata                             | {}                                                         |
   | name                                 | testvm1                                                    |
   | os-extended-volumes:volumes_attached | []                                                         |
   | progress                             | 0                                                          |
   | security_groups                      | default                                                    |
   | status                               | BUILD                                                      |
   | tenant_id                            | 26778b0f745143c5a9b0c7e1a621bb80                           |
   | updated                              | 2017-01-13T13:50:32Z                                       |
   | user_id                              | 7efbea74c20a4eeabc00b7740aa4d353                           |
   +--------------------------------------+------------------------------------------------------------+
   ```
   {: .no-select-button}

1. Check when the VM has booted:

   ```bash
   nova list
   ```

   You should see your VM with the following statuses.

   ```
   +--------------------------------------+---------+--------+------------+-------------+----------------------------------------------+
   | ID                                   | Name    | Status | Task State | Power State | Networks                                     |
   +--------------------------------------+---------+--------+------------+-------------+----------------------------------------------+
   | b6d8a3c4-9674-4972-9151-11107b60d622 | testvm1 | ACTIVE | -          | Running     | demo-net=10.28.0.13, fd5f:5d21:845:1c2e:2::d |
   +--------------------------------------+---------+--------+------------+-------------+----------------------------------------------+
   ```
   {: .no-select-button}

1. Use the following command to obtain the status of the VM.

   ```bash
   nova show testvm1
   ```

   It should return something like the following.

   ```
   +--------------------------------------+------------------------------------------------------------+
   | Property                             | Value                                                      |
   +--------------------------------------+------------------------------------------------------------+
   | OS-DCF:diskConfig                    | MANUAL                                                     |
   | OS-EXT-AZ:availability_zone          | neil-fv-0-ubuntu-kilo-compute-node01                       |
   | OS-EXT-SRV-ATTR:host                 | neil-fv-0-ubuntu-kilo-compute-node01                       |
   | OS-EXT-SRV-ATTR:hypervisor_hostname  | neil-fv-0-ubuntu-kilo-compute-node01                       |
   | OS-EXT-SRV-ATTR:instance_name        | instance-0000000d                                          |
   | OS-EXT-STS:power_state               | 1                                                          |
   | OS-EXT-STS:task_state                | -                                                          |
   | OS-EXT-STS:vm_state                  | active                                                     |
   | OS-SRV-USG:launched_at               | 2017-01-13T13:50:39.000000                                 |
   | OS-SRV-USG:terminated_at             | -                                                          |
   | accessIPv4                           |                                                            |
   | accessIPv6                           |                                                            |
   | config_drive                         |                                                            |
   | created                              | 2017-01-13T13:50:32Z                                       |
   | demo-net network                     | 10.28.0.13, fd5f:5d21:845:1c2e:2::d                        |
   | flavor                               | m1.tiny (1)                                                |
   | hostId                               | bf3ce3c7146ba6cafd43be03886de8755e2b5c8e9f71aa9bfafde9a0   |
   | id                                   | b6d8a3c4-9674-4972-9151-11107b60d622                       |
   | image                                | cirros-0.3.2-x86_64 (b69ab3bd-2bbc-4086-b4ae-f01d9f6b5078) |
   | key_name                             | -                                                          |
   | metadata                             | {}                                                         |
   | name                                 | testvm1                                                    |
   | os-extended-volumes:volumes_attached | []                                                         |
   | progress                             | 0                                                          |
   | security_groups                      | default                                                    |
   | status                               | ACTIVE                                                     |
   | tenant_id                            | 26778b0f745143c5a9b0c7e1a621bb80                           |
   | updated                              | 2017-01-13T13:50:39Z                                       |
   | user_id                              | 7efbea74c20a4eeabc00b7740aa4d353                           |
   +--------------------------------------+------------------------------------------------------------+
   ```
   {: .no-select-button}

   In this example, the VM has been given a fixed IP of 10.28.0.13.  

1. Let's look at the corresponding Neutron port.

   ```bash
   neutron port-list
   ```

   It should look something like the following.

   ```
   +--------------------------------------+------+-------------------+------------------------------------------------------------------------------------------------+
   | id                                   | name | mac_address       | fixed_ips                                                                                      |
   +--------------------------------------+------+-------------------+------------------------------------------------------------------------------------------------+
   | 656b3617-570d-473e-a5dd-90b61cb0c49f |      | fa:16:3e:4d:d5:25 |                                                                                                |
   | 9a7e0868-da7a-419e-a7ad-9d37e11091b8 |      | fa:16:3e:28:a9:a4 | {"subnet_id": "0a1221f2-e6ed-413d-a040-62a266bd0d8f", "ip_address": "10.28.0.13"}              |
   |                                      |      |                   | {"subnet_id": "345fec2e-6493-44de-a489-97b755c16dd4", "ip_address": "fd5f:5d21:845:1c2e:2::d"} |
   | a4b26bcc-ba94-4033-a9fc-edaf151c0c20 |      | fa:16:3e:74:46:bd |                                                                                                |
   | a772a5e1-2f13-4fc3-96d5-fa1c29717637 |      | fa:16:3e:c9:c6:8f |                                                                                                |
   +--------------------------------------+------+-------------------+------------------------------------------------------------------------------------------------+
   ```
   {: .no-select-button}

## Adding a service IP to the Neutron port as an extra fixed IP

Now we want to set up a service IP - let's say `10.28.0.23` - that
initially points to that VM, `testvm1`.  

1. One way to do that is to add the service IP as a second 'fixed IP' on the Neutron port.

   ```bash
   neutron port-update --fixed-ip subnet_id=0a1221f2-e6ed-413d-a040-62a266bd0d8f,ip_address=10.28.0.13 \
   --fixed-ip subnet_id=0a1221f2-e6ed-413d-a040-62a266bd0d8f,ip_address=10.28.0.23 9a7e0868-da7a-419e-a7ad-9d37e11091b8
   ```

1. It should return a confirmation message.

   ```
   Updated port: 9a7e0868-da7a-419e-a7ad-9d37e11091b8
   ```
   {: .no-select-button}

1. Use the following command to get more information about the port.

   ```bash
   neutron port-show 9a7e0868-da7a-419e-a7ad-9d37e11091b8
   ```

   It should return a table like the following.

   ```
   +-----------------------+-----------------------------------------------------------------------------------+
   | Field                 | Value                                                                             |
   +-----------------------+-----------------------------------------------------------------------------------+
   | admin_state_up        | True                                                                              |
   | allowed_address_pairs |                                                                                   |
   | binding:host_id       | neil-fv-0-ubuntu-kilo-compute-node01                                              |
   | binding:profile       | {}                                                                                |
   | binding:vif_details   | {"port_filter": true, "mac_address": "00:61:fe:ed:ca:fe"}                         |
   | binding:vif_type      | tap                                                                               |
   | binding:vnic_type     | normal                                                                            |
   | device_id             | b6d8a3c4-9674-4972-9151-11107b60d622                                              |
   | device_owner          | compute:None                                                                      |
   | extra_dhcp_opts       |                                                                                   |
   | fixed_ips             | {"subnet_id": "0a1221f2-e6ed-413d-a040-62a266bd0d8f", "ip_address": "10.28.0.13"} |
   |                       | {"subnet_id": "0a1221f2-e6ed-413d-a040-62a266bd0d8f", "ip_address": "10.28.0.23"} |
   | id                    | 9a7e0868-da7a-419e-a7ad-9d37e11091b8                                              |
   | mac_address           | fa:16:3e:28:a9:a4                                                                 |
   | name                  |                                                                                   |
   | network_id            | 60651076-af2a-4c6d-8d64-500b53a4e547                                              |
   | security_groups       | 75fccd0a-ef3d-44cd-91ec-ef22941f50f5                                              |
   | status                | ACTIVE                                                                            |
   | tenant_id             | 26778b0f745143c5a9b0c7e1a621bb80                                                  |
   +-----------------------+-----------------------------------------------------------------------------------+
   ```
   {: .no-select-button}

1. Now look at local IP routes.

   ```bash
   ip r
   ```

   We see that we have a route to `10.28.0.23`.

   ```
   default via 10.240.0.1 dev eth0  proto static  metric 100
   10.28.0.13 via 192.168.8.3 dev l2tpeth8-1  proto bird
   10.28.0.23 via 192.168.8.3 dev l2tpeth8-1  proto bird
   [...]
   ```
   {: .no-select-button}

   Note that, on the machine where we're running these commands:

   - BIRD is running, peered with the BIRDs that {{site.prodname}} runs on each compute node.
     That is what causes VM routes (including `10.28.0.23`) to appear here.

   - 192.168.8.3 is the IP of the compute node that is hosting `testvm1`.
   <br><br>

1. We can also double check that `10.28.0.23` has appeared as a local device
   route on the relevant compute node.

   ```bash
   ip r
   ```

   It should return something like the following.

   ```
   default via 10.240.0.1 dev eth0
   10.28.0.13 dev tap9a7e0868-da  scope link
   10.28.0.23 dev tap9a7e0868-da  scope link
   10.240.0.1 dev eth0  scope link
   192.168.8.0/24 dev l2tpeth8-3  proto kernel  scope link  src 192.168.8.3
   192.168.122.0/24 dev virbr0  proto kernel  scope link  src 192.168.122.1
   ```
   {: .no-select-button}

   We also need - because with this approach, data that is addressed to
   `10.28.0.23` will be routed to the VM without any NAT - to tell the VM
   itself that it has the extra `10.28.0.23` address.

1. SSH into the VM.

   ```bash
   core@access-node$ ssh cirros@10.28.0.13
   cirros@10.28.0.13's password:
   ```
   {: .no-select-button}

1. From inside the VM, issue the following command to list the interfaces.

   ```bash
   ip a
   ```

   It should return something like the following.

   ```
   1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue
       link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
       inet 127.0.0.1/8 scope host lo
       inet6 ::1/128 scope host
          valid_lft forever preferred_lft forever
   2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
       link/ether fa:16:3e:28:a9:a4 brd ff:ff:ff:ff:ff:ff
       inet 10.28.0.13/16 brd 10.28.255.255 scope global eth0
       inet6 fe80::f816:3eff:fe28:a9a4/64 scope link
          valid_lft forever preferred_lft forever
   ```
   {: .no-select-button}

1. Next, issue the following command.

   ```bash
   sudo ip a a 10.28.0.23/16 dev eth0
   ```

1. List the interfaces again.

   ```bash
   ip a
   ```

   The interfaces should now look more like the following.

   ```
   1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue
       link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
       inet 127.0.0.1/8 scope host lo
       inet6 ::1/128 scope host
          valid_lft forever preferred_lft forever
   2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
       link/ether fa:16:3e:28:a9:a4 brd ff:ff:ff:ff:ff:ff
       inet 10.28.0.13/16 brd 10.28.255.255 scope global eth0
       inet 10.28.0.23/16 scope global secondary eth0
       inet6 fe80::f816:3eff:fe28:a9a4/64 scope link
          valid_lft forever preferred_lft forever
   ```
   {: .no-select-button}

1. Exit the SSH session.

   ```
   Connection to 10.28.0.13 closed.
   ```
   {: .no-select-button}

1. And now we can access the VM on its service IP, as shown below.

   ```bash
   core@access-node$ ssh cirros@10.28.0.23
   The authenticity of host '10.28.0.23 (10.28.0.23)' can't be established.
   RSA key fingerprint is 65:a5:b0:0c:e2:c4:ac:94:2a:0c:64:b8:bc:5a:aa:66.
   Are you sure you want to continue connecting (yes/no)? yes

   Warning: Permanently added '10.28.0.23' (RSA) to the list of known hosts.
   cirros@10.28.0.23's password:
   $
   ```
   {: .no-select-button}

   Note that we already have security set up that allows SSH to the instance from
   our access machine (`192.168.8.1`).

1. You can check this by listing the security groups.

   ```bash
   neutron security-group-list
   ```

   It should return something like the following.

   ```
   +--------------------------------------+---------+----------------------------------------------------------------------+
   | id                                   | name    | security_group_rules                                                 |
   +--------------------------------------+---------+----------------------------------------------------------------------+
   | 75fccd0a-ef3d-44cd-91ec-ef22941f50f5 | default | egress, IPv4                                                         |
   |                                      |         | egress, IPv6                                                         |
   |                                      |         | ingress, IPv4, 22/tcp, remote_ip_prefix: 192.168.8.1/32              |
   |                                      |         | ingress, IPv4, remote_group_id: 75fccd0a-ef3d-44cd-91ec-ef22941f50f5 |
   |                                      |         | ingress, IPv6, remote_group_id: 75fccd0a-ef3d-44cd-91ec-ef22941f50f5 |
   | 903d9936-ce72-4756-a2cc-7c95a846e7e5 | default | egress, IPv4                                                         |
   |                                      |         | egress, IPv6                                                         |
   |                                      |         | ingress, IPv4, 22/tcp, remote_ip_prefix: 192.168.8.1/32              |
   |                                      |         | ingress, IPv4, remote_group_id: 903d9936-ce72-4756-a2cc-7c95a846e7e5 |
   |                                      |         | ingress, IPv6, remote_group_id: 903d9936-ce72-4756-a2cc-7c95a846e7e5 |
   +--------------------------------------+---------+----------------------------------------------------------------------+
   ```
   {: .no-select-button}

## Moving the service IP to another VM

Service IPs are often used for HA, so need to be moved to target a different VM
if the first one fails for some reason (or if the HA system just decides to
cycle the active VM).

1. To demonstrate that we create a second test VM.

   ```bash
   nova boot --flavor m1.tiny --image cirros-0.3.2-x86_64 --nic net-name=demo-net testvm2
   ```

1. List the VMs.

   ```bash
   nova list
   ```

   You should see the new VM in the list.

   ```
   +--------------------------------------+---------+--------+------------+-------------+----------------------------------------------+
   | ID                                   | Name    | Status | Task State | Power State | Networks                                     |    +--------------------------------------+---------+--------+------------+-------------+----------------------------------------------+
   | b6d8a3c4-9674-4972-9151-11107b60d622 | testvm1 | ACTIVE | -          | Running     | demo-net=10.28.0.13, 10.28.0.23              |
   | bb4ef5e3-dc77-472e-af6f-3f0d8c3e5a6d | testvm2 | ACTIVE | -          | Running     | demo-net=10.28.0.14, fd5f:5d21:845:1c2e:2::e |
   +--------------------------------------+---------+--------+------------+-------------+----------------------------------------------+
   ```
   {: .no-select-button}

1. Check the ports.

   ```bash
   neutron port-list
   ```

   It should return something like the following.

   ```
   +--------------------------------------+------+-------------------+------------------------------------------------------------------------------------------------+
   | id                                   | name | mac_address       | fixed_ips                                                                                      |
   +--------------------------------------+------+-------------------+------------------------------------------------------------------------------------------------+
   | 656b3617-570d-473e-a5dd-90b61cb0c49f |      | fa:16:3e:4d:d5:25 |                                                                                                |
   | 7627a298-a2db-4a1a-bc07-9f0f10f58363 |      | fa:16:3e:8e:dc:33 | {"subnet_id": "0a1221f2-e6ed-413d-a040-62a266bd0d8f", "ip_address": "10.28.0.14"}              |
   |                                      |      |                   | {"subnet_id": "345fec2e-6493-44de-a489-97b755c16dd4", "ip_address": "fd5f:5d21:845:1c2e:2::e"} |
   | 9a7e0868-da7a-419e-a7ad-9d37e11091b8 |      | fa:16:3e:28:a9:a4 | {"subnet_id": "0a1221f2-e6ed-413d-a040-62a266bd0d8f", "ip_address": "10.28.0.13"}              |
   |                                      |      |                   | {"subnet_id": "0a1221f2-e6ed-413d-a040-62a266bd0d8f", "ip_address": "10.28.0.23"}              |
   | a4b26bcc-ba94-4033-a9fc-edaf151c0c20 |      | fa:16:3e:74:46:bd |                                                                                                |
   | a772a5e1-2f13-4fc3-96d5-fa1c29717637 |      | fa:16:3e:c9:c6:8f |                                                                                                |
   +--------------------------------------+------+-------------------+------------------------------------------------------------------------------------------------+
   ```
   {: .no-select-button}

1. Remove the service IP from the first VM.

   ```bash
   neutron port-update --fixed-ip subnet_id=0a1221f2-e6ed-413d-a040-62a266bd0d8f,ip_address=10.28.0.13 9a7e0868-da7a-419e-a7ad-9d37e11091b8
   ```

1. And add it to the second.

   ```bash
   neutron port-update --fixed-ip subnet_id=0a1221f2-e6ed-413d-a040-62a266bd0d8f,ip_address=10.28.0.14 \
   --fixed-ip subnet_id=0a1221f2-e6ed-413d-a040-62a266bd0d8f,ip_address=10.28.0.23 7627a298-a2db-4a1a-bc07-9f0f10f58363
   ```

1. SSH into `testvm2`.

   ```bash
   core@access-node$ ssh cirros@10.28.0.14
   The authenticity of host '10.28.0.14 (10.28.0.14)' can't be established.
   RSA key fingerprint is 6a:02:7f:3a:bf:0c:91:de:c4:d6:e7:f6:81:3f:6a:85.
   Are you sure you want to continue connecting (yes/no)? yes

   Warning: Permanently added '10.28.0.14' (RSA) to the list of known hosts.
   cirros@10.28.0.14's password:
   ```
   {: .no-select-button}

1. Tell `testvm2` that it now has the service IP `10.28.0.23`.

   ```bash
   sudo ip a a 10.28.0.23/16 dev eth0
   ```

1. Now connections to `10.28.0.23` go to `testvm2`

   ```bash
   core@access-node$ ssh cirros@10.28.0.23
   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
   @    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
   @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
   IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!
   Someone could be eavesdropping on you right now (man-in-the-middle attack)!
   It is also possible that a host key has just been changed.
   The fingerprint for the RSA key sent by the remote host is
   6a:02:7f:3a:bf:0c:91:de:c4:d6:e7:f6:81:3f:6a:85.
   Please contact your system administrator.
   Add correct host key in /home/core/.ssh/known_hosts to get rid of this message.
   Offending RSA key in /home/core/.ssh/known_hosts:4
   RSA host key for 10.28.0.23 has changed and you have requested strict checking.
   Host key verification failed.
   ```
   {: .no-select-button}

1. Remove the `known_hosts` files.

   ```bash
   rm ~/.ssh/known_hosts
   ```

1. Try again to SSH into the VM.

   ```bash
   core@access-node$ ssh cirros@10.28.0.23
   The authenticity of host '10.28.0.23 (10.28.0.23)' can't be established.
   RSA key fingerprint is 6a:02:7f:3a:bf:0c:91:de:c4:d6:e7:f6:81:3f:6a:85.
   Are you sure you want to continue connecting (yes/no)? yes

   Warning: Permanently added '10.28.0.23' (RSA) to the list of known hosts.
   cirros@10.28.0.23's password:
   ```
   {: .no-select-button}

1. Check the host name.

   ```bash
   hostname
   ```

   It should return:

   ```  
   testvm2
   ```
   {: .no-select-button}

1. Check the interfaces.

   ```
   ip a
   ```

   They should look something like the following.

   ```    
   1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue
       link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
       inet 127.0.0.1/8 scope host lo
       inet6 ::1/128 scope host
          valid_lft forever preferred_lft forever
   2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
       link/ether fa:16:3e:8e:dc:33 brd ff:ff:ff:ff:ff:ff
       inet 10.28.0.14/16 brd 10.28.255.255 scope global eth0
       inet 10.28.0.23/16 scope global secondary eth0
       inet6 fe80::f816:3eff:fe8e:dc33/64 scope link
         valid_lft forever preferred_lft forever
   $
   ```
   {: .no-select-button}
