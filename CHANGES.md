# Changelog

## 1.4.1

- Revert setup.py >=1.8 constraint for pbr

## 1.4.0

- Python 3 support
- Revert "DHCP agent: don't directly connect different subnets"
- Update DevStack plugin:
  - so that it can be used in OpenStack CI
  - to get Calico agent from PPA instead of building from source (which allows
    using Calico 2.0)
  - for Xenial
- Get OpenStack CI DevStack/Tempest scenario test passing
- Use neutron-lib imports where possible instead of neutron
- Documentation improvements:
  - on Calico semantics
  - on floating IP support
  - on service IPs
  - correct enable_plugin call in DevStack README
  - then move all user-facing docs to http://docs.projectcalico.org/master/ (as
    networking-calico docs have now stopped being published to
    docs.openstack.org)
- Support and document using Calico with Kuryr
- Update requirements to match OpenStack global requirements
- Refactoring to organize imports and clarify compatibility code
- Show team and repo badges on README
- Handle recent removal of NeutronManager.get_plugin()
- Monkey-patch eventlet before importing urllib3
- Intercept floating IP creation (as well as update) so that floating IPs are
  effective immediately after creation on the Neutron API

## 1.3.1

- Allow Calico with OpenStack to coexist with other orchestrators using Calico.
- Import utility code from core Calico repo, so that networking-calico becomes
  independent of that repo.
- Fix Neutron driver to correctly handle etcd connection being temporarily
  stopped or unavailable.

## 1.3.0

- Host routes support
- Enable DeprecationWarning in test environments
- Avoid 'No handlers found' warnings in test run output
- Support providing custom etcd connection parameters for DHCP agent
- Fix order of arguments in assertEqual
- DHCP agent log to /var/log/neutron instead of .../calico
- Enable usage reporting for Calico/OpenStack deployments
- DevStack bootstrap: Provide Git user name/email config
- Fix IPv6 router advertisements with multiple networks

## 1.2.2

- Ensure that DHCP agent log file directory exists
- DHCP agent: don't directly connect different subnets

## 1.2.0

- py26/py33 are no longer supported by Infra's CI
- remove python 2.6 trove classifier
- (beta) Add floating IP support in OpenStack plugin.
- Update DevStack plugin settings for new Calico core plugin
- Adapt test code for recent change in common Calico code
- DevStack plugin: complete IPv6 support
- DevStack script: better commenting of supported env. variables
- Support master Neutron code (Mitaka) as well as previous releases
- Use Neutron master for DevStack and testing, instead of Liberty
- Improve urllib3/requests unvendoring fix
- DevStack: Don't run calico-dhcp-agent with sudo
- Rewrap all docs to 79 columns
- Add systemd packaging for Calico DHCP agent on Ubuntu/Debian
- Prefix the profile IDs that we program into etcd
- Remove dependency on removed neutron.i18n module
- Debian package version pinning
- Use proper interface of endpoint class from calico package
- Fix NAT internal/external IP naming scheme
- Use network MTU if network_device_mtu not set
- Gracefully handle absence of network_device_mtu option
- Add file handler for dhcp-agent log

## 1.1.3
