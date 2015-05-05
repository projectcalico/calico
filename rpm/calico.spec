%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:           calico
Summary:        Project Calico virtual networking for cloud data centers
Version:        0.18
Release:        1%{?dist}
License:        Apache-2
URL:            http://projectcalico.org
Source0:        calico-%{version}.tar.gz
Source35:	calico-felix.conf
Source45:	calico-felix.service
BuildArch:	noarch


%description
Project Calico is an open source solution for virtual networking in
cloud data centers. Its IP-centric architecture offers numerous
advantages over other cloud networking approaches such as VLANs and
overlays, including scalability, efficiency, and simplicity. It is
designed for a wide range of environments including OpenStack,
lightweight Linux containers (LXCs), bare metal, and Network Functions
Virtualization (NFV).


%package compute
Group:          Applications/Engineering
Summary:        Project Calico virtual networking for cloud data centers
%if 0%{?el6}
Requires:       calico-common, calico-felix, openstack-neutron, iptables, python-argparse
%else
Requires:       calico-common, calico-felix, openstack-neutron, iptables
%endif


%description compute
This package provides the pieces needed on a compute node.

%post compute
if [ $1 -eq 1 ] ; then
    # Initial installation

    # Enable checksum calculation on DHCP responses.  This is needed
    # when sending DHCP responses over the TAP interfaces to guest
    # VMs, as apparently Linux doesn't itself do the checksum
    # calculation in that case.
    iptables -D POSTROUTING -t mangle -p udp --dport 68 -j CHECKSUM --checksum-fill >/dev/null 2>&1 || true
    iptables -A POSTROUTING -t mangle -p udp --dport 68 -j CHECKSUM --checksum-fill

    # Don't reject INPUT and FORWARD packets by default on the compute host.
    iptables -D INPUT -j REJECT --reject-with icmp-host-prohibited >/dev/null 2>&1 || true
    iptables -D FORWARD -j REJECT --reject-with icmp-host-prohibited >/dev/null 2>&1 || true

    # Save current iptables for subsequent reboots.
    iptables-save > /etc/sysconfig/iptables

    # Enable IP forwarding.
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    sysctl -p
fi

%preun compute
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
    :
fi

%postun compute
if [ $1 -ge 1 ] ; then
    # Package upgrade, not uninstall
    :
fi

%package control
Group:          Applications/Engineering
Summary:        Project Calico virtual networking for cloud data centers
Requires:       calico-common, python-six

%description control
This package provides the pieces needed on a controller node.


%package common
Group:          Applications/Engineering
Summary:        Project Calico virtual networking for cloud data centers

%description common
This package provides common files.


%package felix
Group:          Applications/Engineering
Summary:        Project Calico virtual networking for cloud data centers
Requires:       calico-common, ipset, net-tools, python-devel, python-netaddr, python-gevent

%description felix
This package provides the Felix component.

%post felix
%if 0%{?el7}
if [ $1 -eq 1 ] ; then
    # Initial installation
    /usr/bin/systemctl daemon-reload
    /usr/bin/systemctl enable calico-felix
    /usr/bin/systemctl start calico-felix
fi
%endif

%preun felix
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
%if 0%{?el7}
    /usr/bin/systemctl disable calico-felix
    /usr/bin/systemctl stop calico-felix
%else
    /sbin/initctl stop calico-felix >/dev/null 2>&1 || :
%endif
fi

%postun felix
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
install -m 755 utils/diags.sh %{buildroot}%{_bindir}/calico-diags


%clean
rm -rf $RPM_BUILD_ROOT


%files common
%defattr(-,root,root,-)
%{python_sitelib}/calico*
/usr/bin/calico-diags
%doc

%files compute
%defattr(-,root,root,-)
/usr/bin/calico-gen-bird-conf.sh
/usr/bin/calico-gen-bird6-conf.sh
/usr/share/calico/bird/*
%doc

%files control
%defattr(-,root,root,-)
%doc

%files felix
%defattr(-,root,root,-)
/usr/bin/calico-felix
/etc/calico/felix.cfg.example
%if 0%{?el7}
    %{_unitdir}/calico-felix.service
%else
    %{_sysconfdir}/init/calico-felix.conf
%endif
%doc



%changelog
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
