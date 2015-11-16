%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:           networking-calico
Summary:        Project Calico networking for OpenStack/Neutron
Epoch:          1
Version:        1.0.1
Release:        0.5.pre1%{?dist}
License:        Apache-2
URL:            http://docs.openstack.org/developer/networking-calico/
Source0:        networking-calico-%{version}.tar.gz
BuildArch:	noarch


%description
Project Calico is an open source solution for virtual networking in
cloud data centers. It uses IP routing to provide connectivity
between the workloads in a data center that provide or use IP-based
services - whether VMs, containers or bare metal appliances; and
iptables, to impose any desired fine-grained security policy between
those workloads.


%package -n calico-compute
Group:          Applications/Engineering
Summary:        Project Calico networking for OpenStack/Neutron
%if 0%{?el6}
Requires:       calico-common, calico-felix, networking-calico, openstack-neutron, iptables, python-argparse
%else
Requires:       calico-common, calico-felix, networking-calico, openstack-neutron, iptables
%endif


%description -n calico-compute
This package provides the pieces needed on a compute node.

%files -n calico-compute

%post -n calico-compute
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

%preun -n calico-compute
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
    :
fi

%postun -n calico-compute
if [ $1 -ge 1 ] ; then
    # Package upgrade, not uninstall
    :
fi


%package -n calico-control
Group:          Applications/Engineering
Summary:        Project Calico networking for OpenStack/Neutron
Requires:       calico-common, networking-calico

%description -n calico-control
This package provides the pieces needed on a controller node.

%files -n calico-control


%description
This package installs the networking-calico Calico/Neutron
integration code.

%files
%defattr(-,root,root,-)
%{python_sitelib}/networking_calico*
%doc


%prep
%setup -q


%build
%{__python} setup.py build


%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install -O1 --skip-build --root $RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%changelog
* Thu Nov 19 2015 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.0.1-0.5.pre1
  - First release of RPM packaging for networking-calico.
