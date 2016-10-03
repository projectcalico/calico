%{!?python_sitelib: %define python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print get_python_lib()")}

Name:           networking-calico
Summary:        Project Calico networking for OpenStack/Neutron
Epoch:          1
Version:        1.3.1
Release:        1%{?dist}
License:        Apache-2
URL:            http://docs.openstack.org/developer/networking-calico/
Source0:        networking-calico-%{version}.tar.gz
Source45:	calico-dhcp-agent.service
BuildArch:	noarch
Group:          Applications/Engineering
Requires:       python-pbr, python-etcd


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
Requires:       calico-felix, networking-calico, openstack-neutron, iptables, python-argparse
%else
Requires:       calico-felix, networking-calico, openstack-neutron, iptables
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


%package -n calico-dhcp-agent
Group:          Applications/Engineering
Summary:        Project Calico networking for OpenStack/Neutron
Requires:       networking-calico

%description -n calico-dhcp-agent
This package provides the Calico DHCP agent.

%files -n calico-dhcp-agent
%defattr(-,root,root,-)
/usr/bin/calico-dhcp-agent
%{_unitdir}/calico-dhcp-agent.service

%post -n calico-dhcp-agent
%if 0%{?el7}
if [ $1 -eq 1 ] ; then
    # Initial installation
    /usr/bin/systemctl daemon-reload
    /usr/bin/systemctl enable calico-dhcp-agent
    /usr/bin/systemctl start calico-dhcp-agent
fi
%endif

%preun -n calico-dhcp-agent
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
%if 0%{?el7}
    /usr/bin/systemctl disable calico-dhcp-agent
    /usr/bin/systemctl stop calico-dhcp-agent
%endif
fi

%postun -n calico-dhcp-agent
if [ $1 -ge 1 ] ; then
    # Package upgrade, not uninstall
%if 0%{?el7}
    /usr/bin/systemctl condrestart calico-dhcp-agent >/dev/null 2>&1 || :
%endif
fi


%package -n calico-control
Group:          Applications/Engineering
Summary:        Project Calico networking for OpenStack/Neutron
Requires:       networking-calico

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

# For EL7, install systemd service files
%if 0%{?el7}
    install -d -m 755 %{buildroot}%{_unitdir}
    install -p -D -m 755 %{SOURCE45} %{buildroot}%{_unitdir}/calico-dhcp-agent.service
%endif


%clean
rm -rf $RPM_BUILD_ROOT


%changelog
* Mon Oct 03 2016 Neil Jerram <neil@tigera.io> 1:1.3.1-1
  - networking-calico version 1.3.1 release
    - Allow Calico with OpenStack to coexist with other orchestrators using Calico.
    - Import utility code from core Calico repo, so that networking-calico becomes
      independent of that repo.
    - Fix Neutron driver to correctly handle etcd connection being temporarily
      stopped or unavailable.

* Wed Sep 21 2016 Neil Jerram <neil@tigera.io> 1:1.3.0-1
  - networking-calico version 1.3.0 release
    - Host routes support
    - Enable DeprecationWarning in test environments
    - Avoid 'No handlers found' warnings in test run output
    - Support providing custom etcd connection parameters for DHCP agent
    - Fix order of arguments in assertEqual
    - DHCP agent log to /var/log/neutron instead of .../calico
    - Enable usage reporting for Calico/OpenStack deployments
    - DevStack bootstrap: Provide Git user name/email config
    - Fix IPv6 router advertisements with multiple networks

* Thu Jul 28 2016 Neil Jerram <neil@tigera.io> 1:1.2.2-1
  - networking-calico version 1.2.2 release
    - Ensure that DHCP agent log file directory exists
    - DHCP agent: don't directly connect different subnets

* Thu Jul 21 2016 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.2.0-1
  - networking-calico version 1.2.0 release
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

* Wed Mar 02 2016 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.1.3-1
  - Change default host for etcd connections from localhost to 127.0.0.1

* Tue Mar 01 2016 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.1.2-2
  - Make networking-calico package depend on python-pbr

* Mon Feb 29 2016 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.1.2-1
  - Improve workaround for requests/urllib3 vendoring issue

* Fri Feb 26 2016 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.1.0-1
  - Doc: explain networking-calico, to an OpenStack-savvy audience
  - Doc: add some implementation notes
  - Move Calico's mechanism driver to networking-calico
  - devstack/bootstrap.sh: Don't set SERVICE_HOST
  - Various leader election improvements:
  - Remove 'sqlalchemy' from requirements.txt
  - Handle EtcdKeyNotFound in addition to EtcdCompareFailed.
  - Reduce election refresh interval, handle EtcdEventIndexCleared.
  - Fix deadlock in status reporting.
  - Adjust tox and testr config to print coverage.
  - Add TLS support to the Neutron driver's etcd connection.
  - Skip all ports in DHCP agents on different hosts
  - Use standard logging in test code, instead of print
  - Decouple status reporting from etcd polling.
  - Prevent concurrent initialisation of the mechanism driver.
  - Update pbr requirement to match global-requirements
  - New DHCP agent driven by etcd data instead of by Neutron RPC
  - Pass a string to delete_onlink_route instead of an IPNetwork
  - Fix handling of endpoint directory deletion
  - Update test-requirements.txt to fix CI.
  - Add service framework around Calico DHCP agent
  - Don't automatically install and use Calico DHCP agent

* Tue Feb 02 2016 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.0.1-0.7.pre7
  - Add service framework around Calico DHCP agent

* Thu Jan 21 2016 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.0.1-0.6.pre1
  - devstack/bootstrap.sh: Don't set SERVICE_HOST
  - Various leader election improvements
  - Remove 'sqlalchemy' from requirements.txt
  - Handle EtcdKeyNotFound in addition to EtcdCompareFailed
  - Fix deadlock in status reporting
  - Reduce election refresh interval, handle EtcdEventIndexCleared
  - Add TLS support to the Neutron driver's etcd connection
  - Skip all ports in DHCP agents on different hosts
  - Decouple status reporting from etcd polling
  - Use standard logging in test code, instead of print
  - New DHCP agent driven by etcd data instead of by Neutron RPC

* Thu Nov 19 2015 Neil Jerram <Neil.Jerram@metaswitch.com> 1:1.0.1-0.5.pre1
  - First release of RPM packaging for networking-calico.
