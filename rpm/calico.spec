%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:           calico
Summary:        Project Calico virtual networking for cloud data centers
Version:        0.5
Release:        1%{?dist}
License:        Apache-2
URL:            http://projectcalico.org
Source0:        calico-%{version}.tar.gz
Source15:	calico-compute.init
Source25:	calico-compute.upstart
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

    /sbin/chkconfig --add calico-compute
    /sbin/service calico-compute start >/dev/null 2>&1
fi

%preun compute
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
    /sbin/service calico-compute stop >/dev/null 2>&1
    /sbin/chkconfig --del calico-compute
fi

%postun compute
if [ $1 -ge 1 ] ; then
    # Package upgrade, not uninstall
    /sbin/service calico-compute condrestart >/dev/null 2>&1 || :
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
Requires:       calico-common, ipset, python-pip, python-zmq

%description felix
This package provides the Felix component.

%post felix
if [ $1 -eq 1 ] ; then
    # Initial installation
    pip install python-iptables
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

# Move /usr/etc/* to /etc/*
mv %{buildroot}/usr/etc/* %{buildroot}%{_sysconfdir}/

# Install sysv init scripts
install -p -D -m 755 %{SOURCE15} %{buildroot}%{_initrddir}/calico-compute
install -p -D -m 755 %{SOURCE35} %{buildroot}%{_initrddir}/calico-felix
install -p -D -m 755 %{SOURCE55} %{buildroot}%{_initrddir}/calico-acl-manager

# Install upstart jobs examples
install -p -m 644 %{SOURCE25} %{buildroot}%{_datadir}/calico/
install -p -m 644 %{SOURCE45} %{buildroot}%{_datadir}/calico/
install -p -m 644 %{SOURCE65} %{buildroot}%{_datadir}/calico/


%clean
rm -rf $RPM_BUILD_ROOT


%files common
%defattr(-,root,root,-)
/usr/lib/python2.6/site-packages/calico*
%doc

%files compute
%defattr(-,root,root,-)
/usr/bin/neutron-calico-agent
/usr/bin/calico-gen-bird-conf.sh
/usr/bin/calico-gen-bird6-conf.sh
/etc/neutron/calico_agent.ini
/usr/share/calico/*
%{_initrddir}/calico-compute
%{_datadir}/calico/calico-compute.upstart
%doc

%files control
%defattr(-,root,root,-)
%doc

%files felix
%defattr(-,root,root,-)
/usr/bin/calico-felix
/etc/calico/felix.cfg
%{_initrddir}/calico-felix
%{_datadir}/calico/calico-felix.upstart
%doc

%files acl-manager
%defattr(-,root,root,-)
/usr/bin/calico-acl-manager
/etc/calico/acl_manager.cfg
%{_initrddir}/calico-acl-manager
%{_datadir}/calico/calico-acl-manager.upstart
%doc



%changelog
* Mon Oct 27 2014 Neil Jerram <nj@metaswitch.com> 0.4.1
- New Calico architecture

* Fri Sep 26 2014 Neil Jerram <nj@metaswitch.com> 0.4.1
- Install generator script and template for BIRD6 config

* Tue Sep 16 2014 Neil Jerram <nj@metaswitch.com> 0.4
- Import routes from all ethernet interfaces (in BIRD config)
- Changes to remove unnecessary dependencies on linuxbridge code
- Enhancements for Calico/IPv6 connectivity

* Fri Jul 18 2014 Neil Jerram <nj@metaswitch.com> 0.3
- First RPM-packaged release of Project Calico
