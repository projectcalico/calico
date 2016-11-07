# Changelog

## 2.0.0-beta.3

- Pin logrus to 4b6ea73.
- Pin libcalico-go to v1.0.0-beta-rc2.
- Use 'glide up' to update other Go dependencies.

## 2.0.0-beta.2

- Fix that "nat-outgoing" was not being honoured.

## 2.0.0-beta

- Separate Felix into dataplane driver and dataplane-independent
  parts.  (The initial dataplane driver is the one that uses Linux
  iptables and routing commands; this division will allow us to target
  other dataplane implementations.)
- Rewrite the dataplane-independent part of Felix in Go, for improved
  performance.
- Update calico-diags to collect Upstart logs.
- Improve usage reporting: extra stats, better version number.
- Improve endpoint status reporting.
- Support Kubernetes backend.
- Build system improvements.

## 1.4.4

- Add a retry for deleting conntrack entries.
- calico-diags: include DevStack logs, if present
- Make repo branch for coverage diff configurable
- Add 'this doc has moved' to relevant location in new docs site.
- Update coveralls badge.
- IP SAN support in pyinstaller build
- Add SemaphoreCI badge.
- Pin pycparser version.

## 1.4.3

- Support InterfacePrefix having multiple values, to allow hybrid Calico use by
  OpenStack and Kubernetes/Docker/Mesos at the same time.
- Use PyInstaller-based Felix in calico/felix container build.
- Update Debian and RPM packaging to stop requiring /etc/calico/felix.cfg, as
  Felix itself no longer requires this file to exist.
- Update URLs for the renaming of this repository from 'calico' to 'felix'.

## 1.4.2

- Add CircleCI config
- Fix for baremetal issue (#1071)
- Allow {inbound,outbound}_rules to be omitted, and handle as []
- Add IgnoreLooseRPF config parameter
- Handle interface renaming
- Documentation improvements:
  - Add EtcdEndpoints to Felix configuration reference.
  - Improve overview documentation about Calico security.
  - Update recommended RPM repo for Calico with Liberty or later
- Add Usage Reporting to Felix
- Allow customization of 'etcdctl' for calico-diags
- Add config option to disable IPv6
- Reduce EtcdWatcher timeout to 10s
- Increase urllib3 log severity to avoid log spam from EtcdWatcher

## 1.4.0

- Fix example policy in bare metal docs to be valid json
- Use a different conntrack command to trigger module load.
- Missing conntrack requires conntrack, not iptables
- Allow missing or "default" for tier order.
- Updates for transition to Tigera. (#1055, #1049)
- specified coverage >=4.02,<4.1 to work around #1057
- Fix hypothesis test for label validation. (#1060)
- Default to using system certificate store.
- Fix that conntrack rules only RETURNed packets rather than ACCEPTing.
- Fill in missing log substitution (#1066)
- Add tool to remove all felix iptables/ipsets changes. (#1048)
- Add option to override DROP rules for debugging policy.
- Add log action, and ability to log any rule.

## 1.4.0-pre3

- Add support for securing bare-metal host endpoints.  This is a significant
  change that extends Calico's security model to hosts as well as the
  workloads running on them.
- InterfacePrefix now defaults to "cali", which is a safe default that happens
  to be the correct value for container systems.
- MAC address field in endpoint objects is now optional.  If omitted, the MAC
  address is not policed in iptables.
- Add support for running Felix on RedHat 6.5+ and other distributions with
  glibc 2.12+ and kernel 2.6.32+ via creation of Python 2.7 PyInstaller bundle.
- Fix iptables programming for interfaces with untypically long names.
- Documentation fixes and updates.
- Add Xenial support (systemd configuration for Felix).
- Update CLA process and copyrights for new sponsor Tigera.
- Add Dockerfile metadata labels (as defined at label-schema.org).
- Check that conntrack and iptables are installed at start-of-day.
- Fix that a config section called [DEFAULT] was ignored.
- Simplify upstart job. (#1035)
- Add Timeout to socket.accept(). (#1045)

## 1.4.0-pre2

- Add negation to selector expressions (#1016).
- Add negated match criteria (#1003).
- Fix next-tier action, which incorrectly accepted packets (#1014).
- Update bird config generation scripts.
- Fix conntrack entry deletion (#987).
- Fix iptables retry on commit (#1010).

## 1.4.0-pre1

- Add floating IP support (via 1:1 NAT) in Felix.
- Add tiered security policy based on labels and selectors (PR #979).  Allows
  for a rich, hierarchical security model.

## 1.3.0

- Felix now parses the etcd snapshot in parallel with the event stream;
  this dramatically increases scale when under load.
- Various performance and scale improvements.
- Removed support for Python 2.6.  python-etcd no longer supports 2.6
  as of 0.4.3.
- Add IpInIpTunnelAddr configuration parameter to allow the IP address of
  the IPIP tunnel device to be set.
- Add IptablesMarkMask configuration parameter to control which bits are
  used from the iptables forwarding mark.
- Increase default size of ipsets and make configurable via the
  MaxIpsetSize parameter.
- Bug fixes, including fixes to NAT when using IPIP mode.

## 1.2.2

- Don't report port deletion as an error status.
- Improve leader election performance after restart.
- Catch additional python-etcd exceptions.
- Reduce election refresh interval.
- Resolve "Felix dies if interface missing" on Alpine Linux.
- Rebase to latest 2015.1.2 and 2014.2.4 upstream Ubuntu packages.

## 1.2.1

- Fix Felix ipset exception when using IPIP.
- Use iptables protocol numbers not names.
- Fixes to diagnostics collection scripts.
- Pin networking-calico pip version.
- Really delete routes to ns-* devices in pre-Liberty OpenStack.

## 1.2.0

- Add liveness reporting to Felix.  Felix now reports its liveness into
  etcd and the neutron driver copies that information to the Neutron DB.
  If Felix is down on a host, Neutron will not try to schedule a VM on
  that host.
- Add endpoint status reporting to Felix.  Felix now reports the state of
  endpoints into etcd so that the OpenStack plugin can report this
  information into Neutron.  If Felix fails to configure a port, this now
  causes VM creation to fail.
- Performance enhancements to ipset manipulation.
- Rev python-etcd dependency to 0.4.1.  Our patched python-etcd version
  (which contains additional patches) is still required.
- Reduce occupancy of Felix's tag resolution index in the common case
  where IP addresses only have a single owner.
- Felix now sets the default.rp_filter sysctl to ensure that endpoints
  come up with the Kernel's RPF check enabled by default.
- Optimize Felix's actor framework to reduce message-passing overhead.
- Truncate long output from FailedSystemCall exception.
- Add instructions for use with OpenStack Liberty.

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
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico/CHANGES.md?pixel)](https://github.com/igrigorik/ga-beacon)
