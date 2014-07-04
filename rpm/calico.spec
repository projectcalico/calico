%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:           calico
Summary:        Project Calico virtual networking for cloud data centers
Version:        0.2
Release:        1%{?dist}
License:        Apache-2
URL:            http://projectcalico.org
Source0:        calico-%{version}.tar.gz
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
Requires:       bird, calico-common, neutron-dhcp-agent, iptables-persistent

%description compute
This package provides the pieces needed on a compute node.


%package control
Group:          Applications/Engineering
Summary:        Project Calico virtual networking for cloud data centers
Requires:       calico-common

%description control
This package provides the pieces needed on a controller node.


%package common
Group:          Applications/Engineering
Summary:        Project Calico virtual networking for cloud data centers

%description common
This package provides common files.


%prep
%setup -q


%build
%{__python} setup.py build


%install
rm -rf $RPM_BUILD_ROOT
%{__python} setup.py install -O1 --skip-build --root $RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files common
%defattr(-,root,root,-)
/usr/lib/python2.6/site-packages/calico*
%doc

%files compute
%defattr(-,root,root,-)
/usr/bin/*
/usr/etc/*
/usr/share/calico/*
%doc

%files control
%defattr(-,root,root,-)
%doc



%changelog
