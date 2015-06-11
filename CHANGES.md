# Changelog

## 0.24-dev

- Add support for routing over IP-in-IP interfaces in order to make it 
  easier to evaluate Calico without reconfiguring underlying network.
- Reduce felix occupancy by replacing endpoint dictionaries by "struct"
  objects.
- Allow different hosts to have different interface prefixes for combined
  OpenStack and Docker systems.
- Add missing support for 0 as a TCP port.

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
