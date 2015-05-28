# Changelog

- Firewall input characters in profiles and tags.

## 0.22-dev

- Updated Mechanism driver to specify fixed MAC address for Calico tap
  interfaces.
- Prevent the possibility of gevent context-switching during garbage collection
  in Felix
- Increase the number of file descriptors available to Felix

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
