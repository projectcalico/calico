.. # Copyright (c) Tigera 2016. All rights reserved.
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

Using Calico to Secure Host Interfaces
======================================

This guide describes how to use Calico to secure the network interfaces of
the host itself (as opposed to those of any container/VM workloads that are
present on the host).  We call such interfaces "host endpoints", to distinguish
them from "workload endpoints".

Calico supports the same rich security policy model for host endpoints that it
supports for workload endpoints.  Host endpoints can have labels and tags, and
their labels and tags are in the same "namespace" as those of workload
endpoints.  This allows security rules for either type of endpoint to refer to
the other type (or a mix of the two) using labels and selectors.

Calico does not support setting IPs or policing MAC addresses for host
interfaces, it assumes that the interfaces are configured by the underlying
network fabric.

Calico distinguishes workload endpoints from host endpoints by a configurable
prefix controlled by the ``InterfacePrefix`` configuration value,
(see: :doc:`configuration`). Interfaces that start with the value of
``InterfacePrefix`` are assumed to be workload interfaces.  Others are treated
as host interfaces.

Calico blocks all traffic to/from workload interfaces by default;
allowing traffic only if the interface is known and policy is in place.
However, for host endpoints, Calico is more lenient; it only polices traffic
to/from interfaces that it's been explicitly told about.  Traffic to/from
other interfaces is left alone.

Overview
--------

To make use of Calico's host endpoint support, you will need to follow these
steps, described in more detail below:

- create an etcd cluster
- install Calico's Felix daemon on each host
- initialise the etcd database
- create host endpoint objects in etcd for each interface you want to
  Calico to police (in a later release, we plan to support interface templates
  to remove the need to explicitly configure every interface)
- insert policy into etcd for Calico to apply
- decide whether to disable "failsafe SSH/etcd" access.

Creating an etcd cluster
------------------------

To create a single-node etcd cluster for testing, download an etcd v2.x release
from `the etcd releases archive <https://github.com/coreos/etcd/releases>`_;
we recommend using the most recent bugfix release.  Then follow the
instructions on that page to unpack and run the etcd binary.

To create a production cluster, you should follow the guidance in the
`etcd manual <https://coreos.com/etcd/docs/latest/>`_.  In particular, the
`clustering guide <https://coreos.com/etcd/docs/latest/>`_.

Installing Felix
----------------

There are several ways to install Felix.

- if you are running Ubuntu 14.04, then you can install a version from our
  PPA::

      sudo apt-add-repository ppa:project-calico/calico-<version>
      sudo apt-get update
      sudo apt-get upgrade
      sudo apt-get install calico-felix


  As of writing, <version> should be 1.4.

- if you are running a RedHat 7-derived distribution, you can install from
  our RPM repository::

      cat > /etc/yum.repos.d/calico.repo <<EOF
      [calico]
      name=Calico Repository
      baseurl=http://binaries.projectcalico.org/rpm_stable/
      enabled=1
      skip_if_unavailable=0
      gpgcheck=1
      gpgkey=http://binaries.projectcalico.org/rpm/key
      priority=97
      EOF

      yum install calico-felix


- if you are running another distribution, follow the instructions in
  :doc:`pyi-bare-metal-install` to use our installer bundle.

Until you initialise the database, Felix will make a regular log that it is in
state "wait-for-ready".  The default location for the log file is
``/var/log/calico/felix.log``.

Initialising the etcd database
------------------------------

Calico doesn't (yet) have a tool to initialise the database for bare-metal.  To
initialise the database manually, make sure the ``etcdctl`` tool (which ships
with etcd) is available, then execute the following commands on one of your
etcd hosts::

    etcdctl set /calico/v1/Ready true


If you check the felix logfile after this step, the logs should transition from
periodic notifications that felix is in state "wait-for-ready" to a stream
of initialisation messages.

Creating host endpoint objects
------------------------------

For each host endpoint that you want Calico to secure, you'll need to create
a host endpoint object in etcd.  At present, this must be done manually using
``etcdctl set <key> <value>``.

There are two ways to specify the interface that a host endpoint should refer
to.  You can either specify the name of the interface or its expected IP
address.  In either case, you''ll also need to know the hostname of the
host that owns the interface.

For example, to secure the interface named ``eth0`` with IP 10.0.0.1 on host
``my-host``, you could create a host endpoint object at
``/calico/v1/host/<hostname>/endpoint/<endpoint-id>`` (where ``<hostname>`` is
the hostname of the host with the endpoint and ``<endpoint-id>`` is an
arbitrary name for the interface, such as "data-1" or "management") with the
following data::

    {
      "name": "eth0",
      "expected_ipv4_addrs": ["10.0.0.1"],
      "profile_ids": [<list of profile IDs>],
      "labels": {
        "role": "webserver",
        "environment": "production",
      }
    }


.. note:: Felix tries to detect the correct hostname for a system.  It logs
          out the value it has determined at start-of-day in the following
          format::

              2015-10-20 17:42:09,813 [INFO][30149/5] calico.felix.config 285: Parameter FelixHostname (Felix compute host hostname) has value 'my-hostname' read from None

          The value (in this case "my-hostname") needs to match the hostname
          used in etcd.  Ideally, the host's system hostname should be set
          correctly but if that's not possible, the Felix value can be
          overridden with the FelixHostname configuration setting.  See
          :doc:`configuration` for more details.

Where ``<list of profile IDs>`` is an optional list of security profiles to
apply to the endpoint and labels contains a set of arbitrary key/value pairs
that can be used in selector expressions. For more information on profile IDs,
labels, and selector expressions please see :doc:`etcd-data-model`.

.. warning:: When rendering security rules on other hosts, Calico uses the
             ``expected_ipvX_addrs`` fields to resolve tags and label selectors
             to IP addresses.  If the ``expected_ipvX_addrs`` fields are
             omitted then security rules that use labels and tags will fail
             to match this endpoint.

Or, if you knew that the IP address should be 10.0.0.1, but not the name of the
interface::

    {
      "expected_ipv4_addrs": ["10.0.0.1"],
      "profile_ids": [<list of profile IDs>],
      "labels": {
        "role": "webserver",
        "environment": "production",
      }
    }


The format of a host endpoint object is described in detail in
:doc:`etcd-data-model`.

After you create host endpoint objects, Felix will start policing traffic
to/from that interface.  If you have no policy or profiles in place, then you
should see traffic being dropped on the interface.

.. note:: By default, Calico has a failsafe in place that whitelists certain
          traffic such as ssh.  See below for more details on
          disabling/configuring the failsafe rules.

If you don't see traffic being dropped, check the hostname, IP address and
(if used) the interface name in the configuration.  If there was something
wrong with the endpoint data, Felix will log a validation error at ``WARNING``
level and it will ignore the endpoint::

    $ grep "Validation failed" /var/log/calico/felix.log
    2016-05-31 12:16:21,651 [WARNING][8657/3] calico.felix.fetcd 1017: Validation failed for host endpoint HostEndpointId<eth0>, treating as missing: 'name' or 'expected_ipvx_addr' must be present.; '{ "labels": {"foo": "bar"}, "expected_ipv4_addrs": ["192.168.171.128"], "profile_ids": ["prof1"]}'

The error can be quite long but it should log the precise cause of the
rejection; in this case "'name' or 'expected_ipvx_addr' must be present" tells
us that either the interface's name or its expected IP address must be
specified.

Creating security policy
------------------------

We recommend using tiered policy with bare-metal workloads.  This allows
ordered policy to be applied to endpoints that match particular label
selectors.

At a minimum, you'll need to create a policy tier.  Since tiers are ordered,
we need to specify an order key (lower numbers are applied to traffic first)::

    etcdctl set /calico/v1/policy/tier/my-tier/metadata '{"order": 100}'


Then add at least one policy to the tier.  In this case, we'll allow inbound
traffic to endpoints labeled with role "webserver" on port 80 and all outbound
traffic::

    etcdctl set /calico/v1/policy/tier/my-tier/policy/webserver \
        '{
           "selector": "role==\"webserver\"",
           "order": 100,
           "inbound_rules": [
             {"protocol": "tcp", "dst_ports": [80], "action": "allow"}
           ],
           "outbound_rules": [
             {"action": "allow"}
           ]
         }'


Calico's tiered policy data is described in detail in
:ref:`security-policy-data`.

Failsafe rules
--------------

To avoid completely cutting off a host via incorrect or malformed policy,
Calico has a failsafe mechanism that keeps various pinholes open in the
firewall.

By default, Calico keeps port 22 inbound open on *all* host endpoints, which
allows access to ssh as well as outbound communication to ports 2379, 2380,
4001 and 7001, which allows access to etcd's default ports.

The lists of failsafe ports can be configured via the configuration parameters
described in :doc:`configuration`.  They can be disabled by setting each
configuration value to an empty string.
