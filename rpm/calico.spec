%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:           calico
Summary:        Project Calico virtual networking for cloud data centers
Version:        0.12.1
Release:        1%{?dist}
License:        Apache-2
URL:            http://projectcalico.org
Source0:        calico-%{version}.tar.gz
Source35:	calico-felix.init
Source45:	calico-felix.upstart
Source55:	calico-acl-manager.init
Source65:	calico-acl-manager.upstart
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
Requires:       calico-common, calico-felix, openstack-neutron, iptables

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
Requires:       calico-common, calico-acl-manager

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
Requires:       calico-common, ipset, python-devel, python-zmq, python-netaddr

%description felix
This package provides the Felix component.

%post felix
if [ $1 -eq 1 ] ; then
    # Initial installation
    /sbin/chkconfig --add calico-felix
    /sbin/service calico-felix start >/dev/null 2>&1
fi

%preun felix
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
    /sbin/service calico-felix stop >/dev/null 2>&1
    /sbin/chkconfig --del calico-felix
fi

%postun felix
if [ $1 -ge 1 ] ; then
    # Package upgrade, not uninstall
    /sbin/service calico-felix condrestart >/dev/null 2>&1 || :
fi


%package acl-manager
Group:          Applications/Engineering
Summary:        Project Calico virtual networking for cloud data centers
Requires:       calico-common, python-zmq

%description acl-manager
This package provides the ACL Manager component.

%post acl-manager
if [ $1 -eq 1 ] ; then
    # Initial installation
    /sbin/chkconfig --add calico-acl-manager
    /sbin/service calico-acl-manager start >/dev/null 2>&1
fi

%preun acl-manager
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
    /sbin/service calico-acl-manager stop >/dev/null 2>&1
    /sbin/chkconfig --del calico-acl-manager
fi

%postun acl-manager
if [ $1 -ge 1 ] ; then
    # Package upgrade, not uninstall
    /sbin/service calico-acl-manager condrestart >/dev/null 2>&1 || :
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
install -d -m 755 %{buildroot}%{_initrddir}
install -d -m 755 %{buildroot}%{_sysconfdir}

# Install sysv init scripts
install -p -D -m 755 %{SOURCE35} %{buildroot}%{_initrddir}/calico-felix
install -p -D -m 755 %{SOURCE55} %{buildroot}%{_initrddir}/calico-acl-manager

# Install upstart jobs examples
install -p -m 644 %{SOURCE45} %{buildroot}%{_datadir}/calico/
install -p -m 644 %{SOURCE65} %{buildroot}%{_datadir}/calico/

# Install config and other non-Python files
install -d %{buildroot}%{_sysconfdir}/calico
install etc/*.cfg.example %{buildroot}%{_sysconfdir}/calico
install -d %{buildroot}%{_datadir}/calico/bird
install etc/bird/*.template %{buildroot}%{_datadir}/calico/bird
install -d %{buildroot}%{_bindir}
install -m 755 etc/*.sh %{buildroot}%{_bindir}


%clean
rm -rf $RPM_BUILD_ROOT


%files common
%defattr(-,root,root,-)
%{python_sitelib}/calico*
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
%{_initrddir}/calico-felix
%{_datadir}/calico/calico-felix.upstart
%doc

%files acl-manager
%defattr(-,root,root,-)
/usr/bin/calico-acl-manager
/etc/calico/acl_manager.cfg.example
%{_initrddir}/calico-acl-manager
%{_datadir}/calico/calico-acl-manager.upstart
%doc



%changelog
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
