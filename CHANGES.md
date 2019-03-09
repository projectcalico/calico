# Changelog

## 3.6.0

- Streamline datamodel v1 code
- Adapt frozen DHCP agent code to support Pike
- Enable native handlers for neutron API operations
- Add region config, use for status reporting
- DHCP agent reads subnet info from both old and new paths
- Write v3 resources with region-dependent namespace
- Write subnet data with region-aware etcd path
- Do leader election with region-aware etcd path
- Validate openstack_region value as a DNS label
- Generate label with the OpenStack parent project ID for each VM

## 3.4.0

- Rev version number to match current Calico release.

## 3.3.0

- Make client auth setup compatible with mitaka and earlier

## 3.2.0

- Update requirements handling
- Fix DHCP UT so that it works locally as well as in Zuul CI
- Handle connectivity loss when reading etcd snapshot
- Add endpoint labels for project ID and name, and for SG names

## 3.1.3

- No changes

## 3.1.2

- Always send high-priority port statuses to Neutron.

## 3.1.1

- Ignore tox/env directories when building debs.
- Stop updating port status when Felix times out.
- Improve logs around resyncs.
- Use a priority queue for port status reports.

## 3.1.0

- Try to trigger compaction during OpenStack CI run
- Don't log warnings when it is expected for watch to timeout
- DHCP agent: watch endpoints for this host only
- Monkey-patch etcd3gw's Watcher to avoid socket leak
- Chunk up etcd prefix reads into batches.
- Set default etcd port to 2379
- DHCP agent: take hostname from Neutron 'host' config

## 2.0.0

- Adapt for new Calico data model (v3)
- Transition remaining uses of etcdv2 to etcdv3
- Disambiguate DHCP agent's subnet lookup for an endpoint
- Model security groups as NetworkPolicy instead of Profiles
- Ensure that all Calico driver/plugin code logs consistently
- Change Calico policy and labels prefix
- Initialize privsep infrastructure for Calico DHCP agent
- DHCP agent: Handle endpoint with no ipNetworks
- Fix watch loops to handle compaction

## 1.4.3

- Change _log.warn (now somewhat deprecated) to _log.warning
- Handle FloatingIP move to neutron.db.models.l3
- Handle neutron.context move to neutron-lib
- Fix Neutron common config import error
- DevStack plugin: fix for recent neutron and devstack changes
- Fix networking-calico CI (against master OpenStack)
- Fix networking-calico CI (interface.OPTS move)

## 1.4.2

- Retry fill_dhcp_udp_checksums() on failure
- For the DevStack plugin, get latest Felix code from Calico 'master' PPA
- Stop testing with Python 3.4 as well as Python 3.5
- Replace basestring with six.string_types

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
