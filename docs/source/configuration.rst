.. # Copyright (c) Metaswitch Networks 2015. All rights reserved.
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

Configuring Calico
==================

This page describes how to configure Calico. We first describe the
configuration of the core Calico component - Felix -
because this is needed, and configured similarly, regardless of the
surrounding environment (OpenStack, Docker, or whatever). Then,
depending on that surrounding environment, there will be some further
configuration of that environment needed, to tell it to talk to the
Calico components.

Currently we have detailed environment configuration only for OpenStack.
Work on other environments is in progress, and this page will be
extended as that happens.

This page aims to be a complete Calico configuration reference, and
hence to describe all the possible fields, files etc. For a more
task-based approach, when installing Calico with OpenStack on Ubuntu or
Red Hat, please see :doc:`ubuntu-opens-install` or
:doc:`redhat-opens-install`.

Calico components
-----------------

The core Calico component is Felix. (Please see
:doc:`architecture` for the Calico architecture.)

Felix (/etc/calico/felix.cfg)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Felix runs on each compute host, and is configured by an ini-style
config file at ``/etc/calico/felix.cfg``.

Felix requires explicit configuration before it can run sensibly,
because it cannot guess where the Calico Plugin might be
running. We provide a sample at ``/etc/calico/felix.cfg.example``; you
should copy this to ``/etc/calico/felix.cfg``, and edit it as guided by
the following documentation, before starting the Felix service.

Settings that require configuration (i.e. that don't have plausible defaults)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+-------------------------+---------------------------------------------------------------------------------------------------------------------------------+
| Setting                 | Meaning                                                                                                                         |
+=========================+=================================================================================================================================+
| global. PluginAddress   | The IP address or domain name of the machine running the plugin. If a domain name, it must resolve on the host running Felix.   |
+-------------------------+---------------------------------------------------------------------------------------------------------------------------------+

Settings with plausible defaults
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

+-------------------------------------------------+-------------+-------------------------------------------------------------------------------------------+
| Setting                                         | Default     | Meaning                                                                                   |
+=================================================+=============+===========================================================================================+
| global. EndpointRetryTimeMillis                 | 500         | The time (in milliseconds) between retries for failed endpoint operations, in             |
|                                                 |             | milliseconds. In practice, this controls the longest time we're prepared to wait on API   |
|                                                 |             | inactivity before we retry any outstanding API operations.                                |
+-------------------------------------------------+-------------+-------------------------------------------------------------------------------------------+
| global. ResyncIntervalSecs                      | 1800        | The time (in seconds) between complete Felix state resyncs. Each time this interval       |
|                                                 |             | passes Felix will ask the Plugin to completely report the state it has, to ensure that    |
|                                                 |             | Felix hasn't accidentally missed anything.                                                |
+-------------------------------------------------+-------------+-------------------------------------------------------------------------------------------+
| global. FelixHostname                           | None        | The hostname Felix reports to the plugin. Should be used if the hostname Felix            |
|                                                 |             | autodetects is incorrect or does not match what the plugin will expect.                   |
+-------------------------------------------------+-------------+-------------------------------------------------------------------------------------------+
| global. MetadataAddr                            | 127.0.0.1   | The IP address or domain name of the server that can answer VM queries for cloud-init     |
|                                                 |             | metadata. In OpenStack, this corresponds to the machine running nova-api (or in Ubuntu,   |
|                                                 |             | nova-api-metadata). A value of 'None' means that Felix should not set up any NAT rule for |
|                                                 |             | the metadata path.                                                                        |
+-------------------------------------------------+-------------+-------------------------------------------------------------------------------------------+
| global. MetadataPort                            | 8775        | The port that metadata queries should be addressed to. This, combined with                |
|                                                 |             | global.MetadataAddr (if not 'None'), is used to set up a NAT rule, from                   |
|                                                 |             | 169.254.169.254:80 to MetadataAddr:MetadataPort. In most cases this should not need to be |
|                                                 |             | changed.                                                                                  |
+-------------------------------------------------+-------------+-------------------------------------------------------------------------------------------+
| global. LocalAddress                            | \*          | The IP address Felix should bind to on the local machine. Allows control if the machine   |
|                                                 |             | has multiple interfaces.                                                                  |
+-------------------------------------------------+-------------+-------------------------------------------------------------------------------------------+
| log. LogFilePath                                | None        | The path to the file that Felix should write its logs to. The default 'None' value means  |
|                                                 |             | that Felix will not log to file, so you must change this if you want logging to file.     |
+-------------------------------------------------+-------------+-------------------------------------------------------------------------------------------+
| log. LogSeverityFile                            | INFO        | The lowest log severity that will be written to the log file in log.LogFilePath. May be   |
|                                                 |             | NONE, to turn off logging to file.                                                        |
+-------------------------------------------------+-------------+-------------------------------------------------------------------------------------------+
| log. LogSeveritySys                             | ERROR       | The lowest log severity that will be written to syslog. May be NONE, to turn off logging  |
|                                                 |             | to syslog.                                                                                |
+-------------------------------------------------+-------------+-------------------------------------------------------------------------------------------+
| log. LogSeverityScreen                          | ERROR       | The lowest log severity that will be written to standard out. May be NONE, to turn off    |
|                                                 |             | logging to standard out.                                                                  |
+-------------------------------------------------+-------------+-------------------------------------------------------------------------------------------+
| connection. ConnectionTimeoutMillis             | 40000       | The length of time, in milliseconds, that a connection must be inactive for before Felix  |
|                                                 |             | considers it timed out and attempts to reconnect.                                         |
+-------------------------------------------------+-------------+-------------------------------------------------------------------------------------------+
| connection. ConnectionKeepaliveIntervalMillis   | 5000        | The length of time, in milliseconds, between each keepalive message Felix sends on the    |
|                                                 |             | connections it sends keepalives on. For obvious reasons, should be lower than             |
|                                                 |             | connection.ConnectionTimeoutMillis.                                                       |
+-------------------------------------------------+-------------+-------------------------------------------------------------------------------------------+

OpenStack environment configuration
-----------------------------------

When running Calico with OpenStack, you also need to configure various
OpenStack components, as follows.

Nova (/etc/nova/nova.conf)
^^^^^^^^^^^^^^^^^^^^^^^^^^

Calico uses the Nova metadata service to provide metadata to VMs,
without any proxying by Neutron. To make that work:

-  An instance of the Nova metadata API must run on every compute node.

-  ``/etc/nova/nova.conf`` must not set
   ``service_neutron_metadata_proxy`` or ``service_metadata_proxy`` to
   ``True``. (The default ``False`` value is correct for a Calico
   cluster.)

Neutron server (/etc/neutron/neutron.conf)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In ``/etc/neutron/neutron.conf`` you need the following settings to
configure the Neutron service.

+------------------------------+----------------------------------------+-------------------------------------------+
| Setting                      | Value                                  | Meaning                                   |
+==============================+========================================+===========================================+
| core\_plugin                 | neutron.plugins.ml2.plugin.Ml2Plugin   | Use ML2 plugin                            |
+------------------------------+----------------------------------------+-------------------------------------------+
| api\_workers                 | 0                                      | Don't use worker threads                  |
+------------------------------+----------------------------------------+-------------------------------------------+
| rpc\_workers                 | 0                                      | Don't use worker threads                  |
+------------------------------+----------------------------------------+-------------------------------------------+
| dhcp\_agents\_per\_network   | 9999                                   | Allow unlimited DHCP agents per network   |
+------------------------------+----------------------------------------+-------------------------------------------+

Optionally -- depending on how you want the Calico mechanism driver to
connect to the Etcd cluster -- you can also set the following options
in the ``[calico]`` section of ``/etc/neutron/neutron.conf``.

+-----------------+-------------------+-------------------------------------------+
| Setting         | Default Value     | Meaning                                   |
+=================+===================+===========================================+
| etcd\_host      | localhost         | The hostname or IP of the etcd node/proxy |
+-----------------+-------------------+-------------------------------------------+
| etcd\_port      | 4001              | The port to use for the etcd node/proxy   |
+-----------------+-------------------+-------------------------------------------+


ML2 (.../ml2\_conf.ini)
^^^^^^^^^^^^^^^^^^^^^^^

In ``/etc/neutron/plugins/ml2/ml2_conf.ini`` you need the following
settings to configure the ML2 plugin.

+--------------------------+---------------+-------------------------------------+
| Setting                  | Value         | Meaning                             |
+==========================+===============+=====================================+
| mechanism\_drivers       | calico        | Use Calico                          |
+--------------------------+---------------+-------------------------------------+
| type\_drivers            | local, flat   | Allow 'local' and 'flat' networks   |
+--------------------------+---------------+-------------------------------------+
| tenant\_network\_types   | local, flat   | Allow 'local' and 'flat' networks   |
+--------------------------+---------------+-------------------------------------+

DHCP agent (.../dhcp\_agent.ini)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In ``/etc/neutron/dhcp_agent.ini`` you need the following settings to
configure the Neutron DHCP agent.

+---------------------+-------------------------+--------------------------------------------------------------------------------------------------------+
| Setting             | Value                   | Meaning                                                                                                |
+=====================+=========================+========================================================================================================+
| interface\_driver   | RoutedInterfaceDriver   | Use Calico's modified DHCP agent support for TAP interfaces that are routed instead of being bridged   |
+---------------------+-------------------------+--------------------------------------------------------------------------------------------------------+
