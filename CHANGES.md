# Changelog

## 0.21-dev

- Support for running multiple neutron-server instances in OpenStack.
- Support for running neutron-server API workers in OpenStack.
- Calico Mechanism Driver now performs leader election to control state
  resynchronization.
- Extended data model to support multiple security profiles per endpoint.
- Calico Mechanism Driver now attempts to delete empty etcd directories.
- Felix no longer leaks memory when etcd directories it watches are deleted.
- Fix error on port creation where the Mechanism Driver would create, delete,
  and then recreate the port in etcd.
