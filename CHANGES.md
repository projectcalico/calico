# Changelog

## 1.1.0

- Improve the documentation about upgrading a Calico/OpenStack system.
- Fix compatibility with latest OpenStack code (oslo_config).
- Use posix_spawn to improve Felix's performance under heavy load.
- Explicitly use and enable the kernel's reverse path filtering function,
  and remove our iptables anti-spoofing rules, which were not as robust.

## 1.0.0

- Add support for setting MTU on IP-in-IP device.
- Enhance BIRD configuration and documentation for graceful restart.

## 0.28

- Felix now restarts if its etcd configuration changes.
- Felix now periodically refreshes iptables to be robust to other processes
  corrupting its chains.
- More thorough resynchronization of etcd from the Neutron mechanism driver.
- Added process-specific information to the diagnostics dumps from Felix.

## 0.27

- Limit number of concurrent shell-outs in felix to prevent file descriptor
  exhaustion.
- Have felix periodically resync from etcd and force-refresh the dataplane.
- Stop restarting Felix on Ubuntu if it fails more than 5 times in 10 seconds.
- Move DHCP checksum calculation to Neutron.
- Get all fixed IPs for a port.

## 0.26

- Update and improve security model documentation.
- Streamline conntrack rules, move them to top-level chains to avoid
  duplication.
- Narrow focus of input iptables chain so that it only applies to
  Calico-handled traffic.
- Provide warning log when attempting to use Neutron networks that are not of
  type 'local' or 'flat' with Calico.
- Handle invalid JSON in IPAM key in etcd.
- Move all log rotation into logrotate and out of Felix, to prevent conflicts.
- Change log rotation strategy for logrotate to not rotate small log files.
- Delay starting the Neutron resynchronization thread until after all the
  necessary state has been configured, to avoid race conditions.
- Prevent systemd restarting Felix when it is killed by administrators.

## 0.25

- Remove stale conntrack entries when an endpoint's IP is removed.
- #672: Fix bug where profile chain was left empty instead of being
  stubbed out.
- Improve security between endpoint and host and simplify INPUT chain logic.

## 0.24

- Add Felix statistics logging on USR1 signal.
- Add support for routing over IP-in-IP interfaces in order to make it
  easier to evaluate Calico without reconfiguring underlying network.
- Reduce felix occupancy by replacing endpoint dictionaries by "struct"
  objects.
- Allow different hosts to have different interface prefixes for combined
  OpenStack and Docker systems.
- Add missing support for 0 as a TCP port.
- Add support for arbitrary IP protocols.
- Intern various IDs in felix to reduce occupancy.
- Fix bug where Calico may not propagate security group rule changes from
  OpenStack.
- Reduced logspam from Calico Mechanism Driver.

## 0.23

- Reset ARP configuration when endpoint MAC changes.
- Forget about profiles when they are deleted.
- Treat bad JSON as missing data.
- Add instructions for Kilo on RHEL7.
- Extend diagnostics script to collect etcd and RabbitMQ information.
- Improve BIRD config to prevent NETLINK: File Exists log spam.
- Reduce Felix logging volume.

## 0.22

- Updated Mechanism driver to specify fixed MAC address for Calico tap
  interfaces.
- Prevent the possibility of gevent context-switching during garbage collection
  in Felix.
- Increase the number of file descriptors available to Felix.
- Firewall input characters in profiles and tags.
- Implement tree-based dispatch chains to improve IPTables performance with
  many local endpoints.
- Neutron mechanism driver patches and docs for OpenStack Kilo release.
- Correct IPv6 documentation for Juno and Kilo.

## 0.21

- Support for running multiple neutron-server instances in OpenStack.
- Support for running neutron-server API workers in OpenStack.
- Calico Mechanism Driver now performs leader election to control state
  resynchronization.
- Extended data model to support multiple security profiles per endpoint.
- Calico Mechanism Driver now attempts to delete empty etcd directories.
- Felix no longer leaks memory when etcd directories it watches are deleted.
- Fix error on port creation where the Mechanism Driver would create, delete,
  and then recreate the port in etcd.
- Handle EtcdKeyNotFound from atomic delete methods
- Handle etcd cluster ID changes on API actions
- Fix ipsets cleanup to correctly iterate through stopping ipsets
- Ensure that metadata is not blocked by over-restrictive rules on outbound
  traffic
- Updates and clarifications to documentation
