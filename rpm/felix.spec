%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:           felix
Summary:        Project Calico virtual networking for cloud data centers
Version:        2.0.0
Release:        0.1.rc2%{?dist}
License:        Apache-2
URL:            http://projectcalico.org
Source0:        felix-%{version}.tar.gz
Source1:        calico-felix.logrotate
Source35:       calico-felix.conf
Source45:       calico-felix.service
BuildArch:      x86_64


%define _unpackaged_files_terminate_build 0


%description
Project Calico is an open source solution for virtual networking in
cloud data centers. Its IP-centric architecture offers numerous
advantages over other cloud networking approaches such as VLANs and
overlays, including scalability, efficiency, and simplicity. It is
designed for a wide range of environments including OpenStack,
lightweight Linux containers (LXCs), bare metal, and Network Functions
Virtualization (NFV).


%package -n calico-common
Group:          Applications/Engineering
Summary:        Project Calico virtual networking for cloud data centers

%description -n calico-common
This package provides common files.


%package -n calico-felix
Group:          Applications/Engineering
Summary:        Project Calico virtual networking for cloud data centers
Requires:       calico-common, conntrack-tools, ipset, iptables, iptables-utils, net-tools, iproute, which


%description -n calico-felix
This package provides the Felix component.

%post -n calico-felix
%if 0%{?el7}
if [ $1 -eq 1 ] ; then
    # Initial installation
    /usr/bin/systemctl daemon-reload
    /usr/bin/systemctl enable calico-felix
    /usr/bin/systemctl start calico-felix
fi
%endif

%preun -n calico-felix
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
%if 0%{?el7}
    /usr/bin/systemctl disable calico-felix
    /usr/bin/systemctl stop calico-felix
%else
    /sbin/initctl stop calico-felix >/dev/null 2>&1 || :
%endif
fi

%postun -n calico-felix
if [ $1 -ge 1 ] ; then
    # Package upgrade, not uninstall
%if 0%{?el7}
    /usr/bin/systemctl condrestart calico-felix >/dev/null 2>&1 || :
%else
    /sbin/initctl restart calico-felix >/dev/null 2>&1 || :
%endif
fi


%prep
%setup -q


%build
%{__python} setup.py build


%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install -O1 --skip-build --root $RPM_BUILD_ROOT
cd pyi
find . -type d | xargs -I DIR install -d $RPM_BUILD_ROOT/opt/calico-felix/DIR
find . -type f | \
  grep -v -E 'calico-iptables-plugin|calico-felix' | \
  xargs -I FILE install -m 644 FILE $RPM_BUILD_ROOT/opt/calico-felix/FILE
install -m 755 calico-iptables-plugin $RPM_BUILD_ROOT/opt/calico-felix/calico-iptables-plugin
install -m 755 calico-felix $RPM_BUILD_ROOT/opt/calico-felix/calico-felix
find . -type l | xargs -I FILE install FILE $RPM_BUILD_ROOT/opt/calico-felix/FILE
cd ..
pushd $RPM_BUILD_ROOT/usr/bin
ln -s ../../opt/calico-felix/calico-felix ./calico-felix
ln -fs ../../opt/calico-felix/calico-iptables-plugin ./calico-iptables-plugin
popd

# Setup directories
install -d -m 755 %{buildroot}%{_datadir}/calico
install -d -m 755 %{buildroot}%{_sysconfdir}
%if 0%{?el7}
    install -d -m 755 %{buildroot}%{_unitdir}
%else
    install -d -m 755 %{buildroot}%{_sysconfdir}/init
%endif

# For EL6, install upstart jobs
%if 0%{?el6}
    install -p -m 755 %{SOURCE35} %{buildroot}%{_sysconfdir}/init/calico-felix.conf
%endif

# For EL7, install systemd service files
%if 0%{?el7}
    install -p -D -m 755 %{SOURCE45} %{buildroot}%{_unitdir}/calico-felix.service
%endif

# Install config and other non-Python files
install -d %{buildroot}%{_sysconfdir}/calico
install etc/*.cfg.example %{buildroot}%{_sysconfdir}/calico
install -d %{buildroot}%{_datadir}/calico/bird
install etc/bird/*.template %{buildroot}%{_datadir}/calico/bird
install -d %{buildroot}%{_bindir}
install -m 755 etc/*.sh %{buildroot}%{_bindir}

install -d -m 755 %{buildroot}/%{_sysconfdir}/logrotate.d
install    -m 644 %_sourcedir/calico-felix.logrotate    %{buildroot}/%{_sysconfdir}/logrotate.d/calico-felix


%clean
rm -rf $RPM_BUILD_ROOT


%files -n calico-common
%defattr(-,root,root,-)
/usr/bin/calico-diags
/usr/bin/calico-cleanup
/usr/bin/calico-gen-bird-conf.sh
/usr/bin/calico-gen-bird6-conf.sh
/usr/bin/calico-gen-bird-mesh-conf.sh
/usr/bin/calico-gen-bird6-mesh-conf.sh
/usr/share/calico/bird/*
%doc

%files -n calico-felix
%defattr(-,root,root,-)
/usr/bin/calico-felix
/usr/bin/calico-iptables-plugin
/usr/bin/calico-dummydp-plugin
/opt/calico-felix/*
/etc/calico/felix.cfg.example
%if 0%{?el7}
    %{_unitdir}/calico-felix.service
%else
    %{_sysconfdir}/init/calico-felix.conf
%endif
%{_sysconfdir}/logrotate.d/calico-felix
%doc



%changelog
* Thu Dec 01 2016 Neil Jerram <neil@tigera.io> 2.0.0-0.1.rc2
  - Felix 2.0.0-rc2 (from Git commit a98a7a5).
    - Improve early logging configuration (fixes #1156)
      - Default to logging errors.
      - Provide an override environment variable that allows early logging
        to be turned off or increased. (FELIX_EARLYLOGSEVERITYSCREEN)
    - Allow access to floating IPs from the Calico host as well as from
      further afield.
    - Fix that clusterType was being defaulted when clusterGUID was missing.
    - Incorporate latest libcalico-go improvements (v1.0.0-rc1)
    - Update for current logrus API (fixes #1162)
    - Improve release process for Felix
    - Update libcalico-go to v1.0.0-rc2

* Mon Nov 07 2016 Neil Jerram <neil@tigera.io> 2.0.0-0.3.beta3
  - felix version 2.0.0-0.3.beta3 release
    - Pin logrus to 4b6ea73.
    - Pin libcalico-go to v1.0.0-beta-rc2.
    - Use 'glide up' to update other Go dependencies.

* Fri Nov 04 2016 Neil Jerram <neil@tigera.io> 2.0.0-0.2.beta2
  - felix version 2.0.0-0.2.beta2 release
    - Fix that nat-outgoing was not being honoured.

* Fri Nov 04 2016 Neil Jerram <neil@tigera.io> 2.0.0-0.1.beta
  - felix version 2.0.0-0.1.beta release
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

* Mon Oct 31 2016 Neil Jerram <neil@tigera.io> 1.4.4-1
  - felix version 1.4.4 release
    - Add a retry for deleting conntrack entries.
    - calico-diags: include DevStack logs, if present
    - Make repo branch for coverage diff configurable
    - Add 'this doc has moved' to relevant location in new docs site.
    - Update coveralls badge.
    - IP SAN support in pyinstaller build
    - Add SemaphoreCI badge.
    - Pin pycparser version.

* Mon Oct 03 2016 Neil Jerram <neil@tigera.io> 1.4.3-1
  - calico version 1.4.3 release
    - Support InterfacePrefix having multiple values, to allow hybrid Calico use by
      OpenStack and Kubernetes/Docker/Mesos at the same time.
    - Use PyInstaller-based Felix in calico/felix container build.
    - Update Debian and RPM packaging to stop requiring /etc/calico/felix.cfg, as
      Felix itself no longer requires this file to exist.
    - Update URLs for the renaming of this repository from 'calico' to 'felix'.

* Wed Sep 21 2016 Neil Jerram <neil@tigera.io> 1.4.2-1
  - Calico version 1.4.2
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

* Fri Jul 22 2016 Neil Jerram <neil@tigera.io> 1.4.0-1
  - Calico version 1.4.0 release
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

* Mon Jun 27 2016 Neil Jerram <neil@tigera.io> 1.4.0-0.3.pre
  - calico pre-release (from Git commit 4b1a68)
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

* Thu Feb 25 2016 Shaun Crampton <shaun@projectcalico.org> 1.3.0-1
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

* Tue Jan 12 2016 Matt Dupre <matt@projectcalico.org> 1.3.0-0.6.pre
  - Pre-release of 1.3.0.

* Thu Dec 10 2015 Matt Dupre <matt@projectcalico.org> 1.2.2-1
  - Don't report port deletion as an error status.
  - Improve leader election performance after restart.
  - Catch additional python-etcd exceptions.
  - Reduce election refresh interval.
  - Resolve "Felix dies if interface missing" on Alpine Linux.
  - Rebase to latest 2015.1.2 and 2014.2.4 upstream Ubuntu packages.

* Fri Nov 13 2015 Matt Dupre <matt@projectcalico.org> 1.2.1-1
  - Fix Felix ipset exception when using IPIP.
  - Use iptables protocol numbers not names.
  - Fixes to diagnostics collection scripts.
  - Pin networking-calico pip version.
  - Really delete routes to ns-* devices in pre-Liberty OpenStack.

* Mon Oct 26 2015 Matt Dupre <matt@projectcalico.org> 1.2.0-1
  - Truncate long output from FailedSystemCall exception.
  - Add instructions for use with OpenStack Liberty.

* Mon Oct 19 2015 Matt Dupre <matt@projectcalico.org> 1.2.0-0.2.pre
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

* Tue Sep 08 2015 Neil Jerram <Neil.Jerram@metaswitch.com> 1.1.0
  - Improve the documentation about upgrading a Calico/OpenStack system.
  - Fix compatibility with latest OpenStack code (oslo_config).
  - Use posix_spawn to improve Felix's performance under heavy load.
  - Explicitly use and enable the kernel's reverse path filtering
    function, and remove our iptables anti-spoofing rules, which were not
    as robust.

* Fri Aug 14 2015 Matt Dupre <matt@projectcalico.org> 1.0.0-1
  - Calico version 1.0.0 release

* Tue Aug 10 2015 Matt Dupre <matt@projectcalico.org> 0.29~rc1
  - First release candidate

* Tue Aug 04 2015 Matt Dupre <matt@projectcalico.org> 0.28
  - Felix now restarts if its etcd configuration changes.
  - Felix now periodically refreshes iptables to be robust to other processes
    corrupting its chains.
  - More thorough resynchronization of etcd from the Neutron mechanism driver.
  - Added process-specific information to the diagnostics dumps from Felix.

* Wed Jul 15 2015 Matt Dupre <matt@projectcalico.org> 0.27.1
  - Interim bug-fix release - reinstate DHCP checksum calculation rule.

* Tue Jul 14 2015 Matt Dupre <matt@projectcalico.org> 0.27
  - Limit number of concurrent shell-outs in felix to prevent file descriptor
    exhaustion.
  - Have felix periodically resync from etcd and force-refresh the dataplane.
  - Stop restarting Felix on Ubuntu if it fails more than 5 times in 10 seconds.
  - Move DHCP checksum calculation to Neutron.
  - Get all fixed IPs for a port.

* Mon Jun 29 2015 Cory Benfield <cory@projectcalico.org> 0.26
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

* Mon Jun 22 2015 Cory Benfield <cory@projectcalico.org> 0.25
  - Remove stale conntrack entries when an endpoint's IP is removed.
  - #672: Fix bug where profile chain was left empty instead of being
    stubbed out.
  - Improve security between endpoint and host and simplify INPUT chain logic.

* Mon Jun 15 2015 Cory Benfield <cory@projectcalico.org> 0.24
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

* Mon Jun 08 2015 Matt Dupre <matt@projectcalico.org> 0.23
  - Reset ARP configuration when endpoint MAC changes.
  - Forget about profiles when they are deleted.
  - Treat bad JSON as missing data.
  - Add instructions for Kilo on RHEL7.
  - Extend diagnostics script to collect etcd and RabbitMQ information.
  - Improve BIRD config to prevent NETLINK: File Exists log spam.
  - Reduce Felix logging volume.

* Tue Jun 02 2015 Matt Dupre <matt@projectcalico.org> 0.22.1
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

* Tue May 26 2015 Matt Dupre <matt@projectcalico.org> 0.21
  - Support for running multiple neutron-server instances in OpenStack
  - Support for running neutron-server API workers in OpenStack
  - Calico Mechanism Driver now performs leader election to control state
    resynchronization
  - Extended data model to support multiple security profiles per endpoint
  - Calico Mechanism Driver now attempts to delete empty etcd directories
  - Felix no longer leaks memory when etcd directories it watches are deleted
  - Fix error on port creation where the Mechanism Driver would create, delete,
    and then recreate the port in etcd
  - Handle EtcdKeyNotFound from atomic delete methods
  - Handle etcd cluster ID changes on API actions
  - Fix ipsets cleanup to correctly iterate through stopping ipsets
  - Ensure that metadata is not blocked by over-restrictive rules on outbound
    traffic
  - Updates and clarifications to documentation

* Mon May 18 2015 Matt Dupre <matt@projectcalico.org> 0.20
  - Felix graceful restart support
  - Refactoring and additional unit testing

* Mon May 11 2015 Neil Jerram <neil@projectcalico.org> 0.19
- Further fixes and improvements to Calico components
  - Add script that automates the merging required for a Debian/Ubuntu package
  - Actually save off the endpoints in the endpoint index.
  - Fix reference leak in felix caused by reference cycle.
  - Core review markups and cleanups to ref-tracking code.
  - Add FV-level test that genuinely leaks an exception.

* Tue May 05 2015 Neil Jerram <neil@projectcalico.org> 0.18
- Further fixes and improvements to Calico components
  - Note that RHEL 6.5 instructions are not yet complete
  - Document that Felix requires a config file, or it won't start on RHEL
  - Tidy up line wrapping in RHEL install docs
  - Move utility functions to frules
  - Minor code tidies in dispatch.py
  - Refactor DispatchManager API to not use dicts
  - Add unit tests for DispatchChains
  - Clarify DispatchChains comparison logic
  - Move common validation code to single place.
  - Reinstate etc after overwriting import.
  - Initial code review markups for iptables updater.
  - Code review markups for fiptables.py.
  - Address some RHEL 7 install instruction issues:
  - Minor grammar markups
  - Fix missing import in common
  - Revert "Initial code review markups for iptables updater."
  - Docstrings for UpdateSplitter
  - Remove invalid module reference
  - Retire RHEL 6.5 instructions until we can fix them up, or are convinced there is no demand.
  - Allow for config to be read from config files.
  - Code review feedback
  - changed bgp_export policy to be interface of origin based
  - Ensure no logs are made to screen in mainline with screen logging disabled
  - syntax cleanup, prettified, and default filter added back in.
  - cut and paste doh... - v4 default address used in v6 config file
  - Work in progress on cleanup/support for anycast IPs.
  - Minor fixes: typos and incorrect indexing into dicts.
  - Fixes and cleanups: move updates into lower level methods.
  - Fix missing delete when cleaning up ip address.
  - Minor cleanups and self-review markups.
  - Code review markups.  Track dirty tags and update en-masse.
  - Revert "Revert "Initial code review markups for iptables updater.""
  - Revert rename of _Transaction.updates, it is referenced by IptablesUpdater.
  - Suppress start-of-day iptables-restore errors from CaS-type operations.
  - Tidy up etcd exception logging.
  - Clean up devices exception logging.
  - Add actor life-cycle logging.
  - Add endpoint and profile IDs as comments in iptables chains.
  - Unit tests for the UpdateSplitter
  - RHEL7 doc: fix formatting of Calico repo config
  - RHEL7 doc: don't mention Icehouse
  - Clarify that mapping is dict
  - Update documentation of configuration for Felix.
  - Felix review and some UT (actor, refcount)
  - Replace endpoint ID with tuple that includes host and workload too.
  - Code review markups to refcount.py.
  - Don't process endpoint creation until SOD complete
  - Docs typo fix: incorrect etcd mount in fstab
  - Remove comments
  - Document the new mailing lists
  - Update involved.rst
  - Plugin: provide correct workload ID - fixes #445
  - Plugin: provide correct workload ID - UT updates
  - Update README.md
  - Cleanup README line length
  - Missing sec group retries
  - Close race between resync and access to self.sgs in plugin.
  - Remove race in needed_profile cleanup by using a semaphore.
  - Be resilient to ports disappearing while loading SG members.
  - Protect all access to the security groups dict.
  - Fix up UT environment to include neutron.common.exceptions.
  - Reinstate ability to take file path as command line parameter.
  - Markups to config file specification - tidy exception handling
  - Wording tweaks based on previous version of config documentation.

* Mon Apr 27 2015 Neil Jerram <neil@projectcalico.org> 0.17
- Bug fixes and improvements to Calico components
  - Clean up config loading (code review markups).
  - Remove references to ACL manager from RHEL docs
  - Etcd install instructions for RHEL
  - Be more defensive in etcd polling, catch various HTTP-related exceptions.
  - Fix import order in felix.py to invoke gevent monkey-patch first.
  - Fix missing arg to log message.
  - Remove incorrect comment.
  - Fix plugin to set only icmp_type/code and not port range for ICMP.
  - Add UTs for ICMP rule generation.
  - Add felix support for ICMP code, firewall values.
  - Validate plugin data agsint felix's validation routines.
  - Code review markups.
  - Fix missing continue: use setting of response as a gate in fetcd.py.
  - Increase severity of socket.timeout warning.
  - Add httplib errors into excepts.
  - Code review markups.
  - Update involved.rst
  - Update contribute.rst
  - Tidy up line lengths
  - Revert "Tidy up line lengths"
  - Tidy up line lengths
  - Don't unnecessarily pin versions
  - Fix up a range of commnents.
  - Cleanup toctree for contribution doc
  - Further README cleanup
  - The letter 'a' is tricksy
  - Update contribute.rst
  - RPM Version 0.16
  - Fix RPM version
  - Beef up syslog format, add a couple of additional logs.
  - Debian packaging: python-gevent is not actually needed on controller
  - RPM packaging: remove ACL manager and ZMQ deps; add python-gevent (fixes #435)
  - Packaging: add dependency of Felix on net-tools, for the arp command (fixes #146)
  - Make ipset uperations idempotent.
  - Fix cluster UUID check.  Copy UUID from old client to new, fix typo in arg name.
  - RHEL install markups
  - Fix my own review markups
  - Run etcd on startup
  - After reboots
  - Copy etcd binaries to the right place
  - Update bundle for etcd architecture
  - Use commit id instead of tag in tox dependency
  - Code review markups.
  - Prevent ActiveIpset from recreating ipset after on_unreferenced().
  - Fix missing stdin argument to Popen, beef up diags for ActiveIpset.
  - Code review markups.
  - Update openstack.rst
  - Don't setuid on RHEL 6.5.
  - Wrapping lines
  - Fix numbering in ubuntu-opens-install.rst
  - Add missing jump target to ICMPv6 from endpoint rule.
  - Add "icmp_code" to whitelist of allowed rule fields.
  - Prevent programming of ICMP type 255, which the kernel treats as wildcard.
  - Isolate rule parsing failure to individual rule.

* Tue Apr 21 2015 Matt Dupre <matt@projectcalico.org> 0.16
- First release with etcd

* Fri Apr 10 2015 Matt Dupre <matthew.dupre@metaswitch.com> 0.15
- Fix exception in Neutron mechanism driver
- Many documentation changes and additions

* Fri Mar 20 2015 Matt Dupre <matthew.dupre@metaswitch.com> 0.14
- Move documentation from separate calico-docs GitHub wiki to Read the Docs
- Neutron mechanism driver fixes

* Fri Mar 06 2015 Matt Dupre <matthew.dupre@metaswitch.com> 0.13
- Bug fixes and enhancements to Calico components
  - Remove python-iptables
  - Add EL6.5 support
  - Make Calico components restart after failures
  - Enhance diagnostics gathering script
  - Fix live migration support
  - Many logging, testing and configuration improvements
  - Improve handling of connection timeouts
  - Program proxy NDP

* Fri Feb 13 2015 Matt Dupre <matthew.dupre@metaswitch.com> 0.12.1
- Bug fixes and improvements to Calico components
  - Initial refactor of fsocket.
  - Fix issue #133 (lost resync when connection error)
  - Fix restart failure on connection error (bug #97)
  - More timing tests, and fixing of resulting bugs.
  - Tighten up resync testing, with bug fix.
  - ACL Manager fix: Suppress superfluous unsolicited ACLUPDATE messages when nothing has changed
  - Use ip route replace instead of add Fixes timing window when route exists during live migration
  - Fix #164: Disable proxy_delay on taps to avoid delayed proxy ARP response.
  - Better doc and organization for setup code
  - mech_calico: Bind as directed by Neutron server's bind_host config
  - Delete routes when endpoint destroyed
  - Send ENDPOINTDESTROYED rsp even whenendpoint is unknown (fixes #192)
  - More robust exception handling in handle_endpoint{updated|destroyed}
  - Unit testing and diagnostics improvements

* Fri Jan 30 2015 Matt Dupre <matthew.dupre@metaswitch.com> 0.11
- Logging improvements and additional unit tests
- ACL Manager fixes
  - Support multiple security groups on a single endpoint
  - ACL Manager stops listening for network updates silently when a rule
    references an empty security group
  - Ensure ACL Manager exits cleanly with a log when worker threads crash

* Fri Jan 23 2015 Matt Dupre <matthew.dupre@metaswitch.com> 0.10.3~rc3
- Add Red Hat 7 support
- Many code fixes and enhancements

* Fri Nov 21 2014 Neil Jerram <nj@metaswitch.com> 0.8
- New fixes and enhancements to Felix
  - Clean up code and tidy up ready so that accept default rules can work.
  - Some trivial code tidy left over from the merges.
  - Minor typo fixes.
  - Code review markups.
  - Fix bug where duplicate rules created.
  - Fix up ICMP rules for all ICMP.
  - Various code review markups ready for merging.
  - Unblock outgoing DHCP. Bug in fix to issue38.
  - Fix more issues with issue38 code.  Allow DHCP for IPv6 too Fix up
    getting in / out interfaces backwards
  - Handle ACLUPDATE for deleted endpoint.
  - Config file tweaks. Comment out values matching defaults.
  - Add Metadata IP and Port configuration to Felix
  - Allow address as well as IP for metadata.
  - Ban traffic to the loopback address from VMs (unless for metadata)

* Tue Nov 11 2014 Neil Jerram <nj@metaswitch.com> 0.7
- Update packaging to support source package creation and upload.
  - Implement install steps in setup.py and debian/rules, instead of setup.cfg.

* Fri Nov 07 2014 Neil Jerram <nj@metaswitch.com> 0.6
- Many fixes and enhancements to Felix (the new Calico agent)
  - IP v6 support and minor bug fixes.
  - Minor logging enhancement.
  - Fix dull bug where we never left long enough for resync responses to return on a slow system, ignoring the config values.
  - Many more updates. Apart from intermittent iptables issues, mostly working well. Next action is to fix those.
  - Finally fix dull issue with python-iptables, state and IPv6.
  - Add ep_retry code.
  - Fix small bugette in handling of endpoint retry.
  - Stop using "state" completely - "conntrack" seems more reliable.
  - Fix up bug where we created IPv6 sets as IPv4, then crashed.
  - GETACLUPDATE response may arrive before tap interface created; handle it.
  - Speculative fix for problem with icmp ip6tables rules.
  - Do not get confused during second resync and delete endpoints.
  - Allow for the state of endpoints to be disabled.
  - Subscribe to ACL heartbeats to avoid timing it out continuously.
  - Minor cosmetic edits.
  - More minor refactoring and code tidy up.
  - Remove IPs from an endpoint when they are removed by the API. Also, some minor code tidies.
  - Clean up logic when removing unused IPs.
  - Fix up dull typo in IP removal code.
  - Fix bug where tap address got wrong MAC address.
  - Put in candidate workaround for looping in iptables configuration.
- Packaging: calico-felix needs dependency on python-dev(el)
- RPM packaging fixes
  - Start and stop Calico services on install/uninstall
  - Run Calico services as root, not as 'neutron'
- ACL Manager fix
  - ACL manager was sending a three part message for keepalives. Make it a two part message like the others.

* Mon Oct 27 2014 Neil Jerram <nj@metaswitch.com> 0.5
- New Calico architecture

* Fri Sep 26 2014 Neil Jerram <nj@metaswitch.com> 0.4.1
- Install generator script and template for BIRD6 config

* Tue Sep 16 2014 Neil Jerram <nj@metaswitch.com> 0.4
- Import routes from all ethernet interfaces (in BIRD config)
- Changes to remove unnecessary dependencies on linuxbridge code
- Enhancements for Calico/IPv6 connectivity

* Fri Jul 18 2014 Neil Jerram <nj@metaswitch.com> 0.3
- First RPM-packaged release of Project Calico
