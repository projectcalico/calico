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

Felix configuration
-------------------

The core Calico component is Felix. (Please see :doc:`architecture`
for the Calico architecture.)

Configuration for Felix is read from one of four possible locations, in order,
as follows.

1. Environment variables.
2. The Felix configuration file.
3. Host specific configuration in etcd.
4. Global configuration in etcd.

The value of any configuration parameter is the value read from the *first*
location containing a value. If not set in any of these locations, most
configuration parameters have defaults, and it should be rare to have to
explicitly set them.

In OpenStack, we recommend putting all configuration into configuration files,
since the etcd database is transient (and may be recreated by the OpenStack
plugin in certain error cases). However, in a Docker environment the use of
environment variables or etcd is often more convenient.

The full list of parameters which can be set is as follows.

+------------------+---------------------------+-------------------------------------------------------------------------------------------+
| Setting          | Default                   | Meaning                                                                                   |
+==================+===========================+===========================================================================================+
| EtcdAddr         | localhost:4001            | The location (IP / hostname and port) of the etcd node or proxy that Felix should connect |
|                  |                           | to.                                                                                       |
+------------------+---------------------------+-------------------------------------------------------------------------------------------+
| FelixHostname    | socket.gethostname()      | The hostname Felix reports to the plugin. Should be used if the hostname Felix            |
|                  |                           | autodetects is incorrect or does not match what the plugin will expect.                   |
+------------------+---------------------------+-------------------------------------------------------------------------------------------+
| MetadataAddr     | 127.0.0.1                 | The IP address or domain name of the server that can answer VM queries for cloud-init     |
|                  |                           | metadata. In OpenStack, this corresponds to the machine running nova-api (or in Ubuntu,   |
|                  |                           | nova-api-metadata). A value of 'None' (case insensitive) means that Felix should not set  |
|                  |                           | up any NAT rule for the metadata path.                                                    |
+------------------+---------------------------+-------------------------------------------------------------------------------------------+
| MetadataPort     | 8775                      | The port of the metadata server. This, combined with global.MetadataAddr (if not 'None'), |
|                  |                           | is used to set up a NAT rule, from 169.254.169.254:80 to MetadataAddr:MetadataPort. In    |
|                  |                           | most cases this should not need to be changed.                                            |
+------------------+---------------------------+-------------------------------------------------------------------------------------------+
| InterfacePrefix  | None                      | The start of the interface name for all interfaces. This is set to "tap" on OpenStack     |
|                  |                           | by the plugin, but must be set to "veth" on most Docker deployments.                      |
+------------------+---------------------------+-------------------------------------------------------------------------------------------+
| LogFilePath      | /var/log/calico/felix.log | The full path to the felix log. Set to "none" to disable file logging.                    |
+------------------+---------------------------+-------------------------------------------------------------------------------------------+
| LogSeveritySys   | ERROR                     | The log severity above which logs are sent to the syslog. Valid values are DEBUG, INFO,   |
|                  |                           | WARNING, ERROR and CRITICAL, or NONE for no logging to syslog (all values case            |
|                  |                           | insensitive).                                                                             |
+------------------+---------------------------+-------------------------------------------------------------------------------------------+
| LogSeverityFile  | INFO                      | The log severity above which logs are sent to the log file. Valid values as for           |
|                  |                           | LogSeveritySys.                                                                           |
+------------------+---------------------------+-------------------------------------------------------------------------------------------+
| LogSeverityScreen| ERROR                     | The log severity above which logs are sent to the stdout. Valid values as for             |
|                  |                           | LogSeveritySys.                                                                           |
+------------------+---------------------------+-------------------------------------------------------------------------------------------+


Environment variables
^^^^^^^^^^^^^^^^^^^^^

The highest priority of configuration is that read from environment
variables. To set a configuration parameter via an environment variable, set
the environment variable formed by taking ``FELIX_`` and appending the uppercase
form of the variable name. For example, to set the etcd address, set the
environment variable ``FELIX_ETCDADDR``.Other examples include
``FELIX_FELIXHOSTNAME``, ``FELIX_LOGFILEPATH`` and ``FELIX_METADATAADDR``.

Configuration file
^^^^^^^^^^^^^^^^^^

On startup, Felix reads an ini-style configuration file. The path to this file
defaults to ``/etc/calico/felix.cfg`` but can be overridden using the ``-c`` or
``--config-file`` options on the command line. If the file exists, then it is
read (ignoring section names) and all parameters are set from it.

etcd configuration
^^^^^^^^^^^^^^^^^^

*etcd configuration cannot be used to set either EtcdAddr or FelixHostname, both of which are required before the etcd configuration can be read.*

etcd configuration is read from etcd from two places.

1. For a host of FelixHostname value ``HOSTNAME`` and a parameter named
   ``NAME``, it is read from ``/calico/v1/host/HOSTNAME/config/NAME``.

2. For a parameter named ``NAME``, it is read from ``/calico/v1/config/NAME``.

Note that the names are case sensitive.

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
